package kernel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skye-z/amz/types"
)

// 抽象 HTTP 代理使用的共享拨号入口，便于后续复用核心隧道。
type HTTPStreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type countingReadCloser struct {
	io.ReadCloser
	count int
}

type countingWriter struct {
	writer  io.Writer
	onWrite func(int)
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.count += n
	return n, err
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if n > 0 && c.onWrite != nil {
		c.onWrite(n)
	}
	return n, err
}

// 注入 HTTP 代理复用的共享 dialer。
func (m *HTTPProxyManager) SetHTTPDialer(dialer HTTPStreamDialer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialer = dialer
	m.transport = nil
}

// 注入 HTTP/3 CONNECT stream 依赖 (2026 L4 Proxy)。
func (m *HTTPProxyManager) SetStreamManager(mgr *ConnectStreamManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamManager = mgr
}

// 注入自定义 round tripper，便于测试覆盖普通 HTTP 转发路径。
func (m *HTTPProxyManager) SetHTTPRoundTripper(roundTripper http.RoundTripper) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transport = roundTripper
}

// 使用核心会话编排 dialer 包装当前 HTTP 代理的共享拨号入口。
func (m *HTTPProxyManager) SetCoreTunnelDialer(connection *ConnectionManager, session *ConnectIPSessionManager, delegate HTTPStreamDialer) error {
	dialer, err := NewCoreTunnelDialer(connection, session, delegate)
	if err != nil {
		return err
	}
	m.SetHTTPDialer(dialer)
	m.SetStreamManager(dialer.StreamManager())
	return nil
}

// 记录启动次数并切换到运行态，同时启动真实 HTTP 代理监听。
func (m *HTTPProxyManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.state == types.StateStopped {
		m.mu.Unlock()
		return errProxyAlreadyStopped
	}
	if m.state == types.StateRunning {
		m.mu.Unlock()
		return nil
	}
	if err := context.Cause(ctx); err != nil {
		m.mu.Unlock()
		return err
	}

	ln, err := net.Listen("tcp", m.listen)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("listen http proxy: %w", err)
	}

	server := &http.Server{
		Handler:     &httpProxyHandler{manager: m},
		BaseContext: func(net.Listener) context.Context { return context.Background() },
	}

	m.listener = ln
	m.server = server
	m.listen = ln.Addr().String()
	m.state = types.StateRunning
	m.stats.StartCount++
	m.logf("http proxy start: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.runWG.Add(1)
	go func() {
		defer m.runWG.Done()
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !isClosedNetworkError(err) {
			m.mu.Lock()
			if m.state == types.StateRunning {
				m.state = types.StateStopped
				m.stats.StopCount++
			}
			m.mu.Unlock()
		}
	}()
	m.mu.Unlock()
	return nil
}

// 记录停止次数并切换到停止态，同时关闭 HTTP 代理监听资源。
func (m *HTTPProxyManager) Stop(context.Context) error {
	m.mu.Lock()
	if m.state == types.StateStopped {
		m.mu.Unlock()
		return nil
	}
	server := m.server
	listener := m.listener
	dialer := m.dialer
	m.server = nil
	m.listener = nil
	m.state = types.StateStopped
	m.stats.StopCount++
	m.logf("http proxy stop: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.mu.Unlock()

	if server != nil {
		_ = server.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	if closer, ok := dialer.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	m.runWG.Wait()
	return nil
}

type httpProxyHandler struct {
	manager *HTTPProxyManager
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Method, http.MethodConnect) {
		h.handleConnect(w, r)
		return
	}
	h.handleForward(w, r)
}

func (h *httpProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	dialer := h.manager.currentHTTPDialer()
	streamMgr := h.manager.currentStreamManager()

	if streamMgr != nil {
		h.handleConnectViaStream(w, r, streamMgr)
		return
	}

	if dialer == nil {
		h.manager.logf("http proxy connect dialer unavailable: target=%s", r.Host)
		http.Error(w, "proxy dialer unavailable", http.StatusBadGateway)
		return
	}

	started := time.Now()
	upstream, err := dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		h.manager.logf("http proxy connect upstream failed: target=%s err=%v", r.Host, err)
		http.Error(w, "connect upstream failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	latency := time.Since(started)
	if latency <= 0 {
		latency = time.Nanosecond
	}
	h.manager.RecordHandshakeLatency(latency)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.manager.logf("http proxy hijack unsupported: target=%s", r.Host)
		http.Error(w, "proxy hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		h.manager.logf("http proxy hijack failed: target=%s err=%v", r.Host, err)
		http.Error(w, "proxy hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	if buffered := rw.Reader.Buffered(); buffered > 0 {
		peek, err := rw.Reader.Peek(buffered)
		if err == nil && len(peek) > 0 {
			written, writeErr := upstream.Write(peek)
			h.manager.AddTxBytes(written)
			if writeErr != nil {
				return
			}
			_, _ = rw.Reader.Discard(buffered)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&countingWriter{writer: upstream, onWrite: h.manager.AddTxBytes}, clientConn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&countingWriter{writer: clientConn, onWrite: h.manager.AddRxBytes}, upstream)
	}()
	wg.Wait()
}

func (h *httpProxyHandler) handleConnectViaStream(w http.ResponseWriter, r *http.Request, streamMgr *ConnectStreamManager) {
	host, port, err := parseHTTPConnectTarget(r.Host)
	if err != nil {
		h.manager.logf("http proxy parse target failed: target=%s err=%v", r.Host, err)
		http.Error(w, "invalid target host", http.StatusBadRequest)
		return
	}

	h.manager.logf("handleConnectViaStream: host=%s port=%s target=%s", host, port, r.Host)
	debug := masqueDebugEnabled() && r.Host == "ipwho.is:443"

	started := time.Now()
	if debug {
		h.manager.logf("masque debug: connect target=%s opening stream", r.Host)
	}
	upstream, err := streamMgr.OpenStream(r.Context(), host, port)
	if err != nil {
		h.manager.logf("http proxy connect stream failed: target=%s err=%v", r.Host, err)
		http.Error(w, "connect stream failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	h.manager.logf("handleConnectViaStream: stream opened successfully, remote=%s", upstream.RemoteAddr())
	if debug {
		h.manager.logf("masque debug: connect target=%s stream ready local=%s remote=%s", r.Host, upstream.LocalAddr(), upstream.RemoteAddr())
	}

	latency := time.Since(started)
	if latency <= 0 {
		latency = time.Nanosecond
	}
	h.manager.RecordHandshakeLatency(latency)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.manager.logf("http proxy hijack unsupported: target=%s", r.Host)
		http.Error(w, "proxy hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		h.manager.logf("http proxy hijack failed: target=%s err=%v", r.Host, err)
		http.Error(w, "proxy hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	if debug {
		h.manager.logf("masque debug: connect target=%s sent 200 established to client", r.Host)
	}

	if buffered := rw.Reader.Buffered(); buffered > 0 {
		if debug {
			h.manager.logf("masque debug: connect target=%s buffered client bytes=%d", r.Host, buffered)
		}
		peek, err := rw.Reader.Peek(buffered)
		if err == nil && len(peek) > 0 {
			written, writeErr := upstream.Write(peek)
			h.manager.AddTxBytes(written)
			if debug {
				h.manager.logf("masque debug: connect target=%s pre-relay upstream write bytes=%d err=%v", r.Host, written, writeErr)
			}
			if writeErr != nil {
				return
			}
			_, _ = rw.Reader.Discard(buffered)
		}
	}

	h.manager.logf("handleConnectViaStream: starting relay")
	relayBidirectional(
		clientConn,
		upstream,
		h.manager.AddTxBytes,
		h.manager.AddRxBytes,
		func(format string, args ...any) {
			if debug || !strings.HasPrefix(format, "masque debug:") {
				h.manager.logf(format, args...)
			}
		},
		r.Host,
	)
	upstream = nil
	h.manager.logf("handleConnectViaStream: relay complete")
}

func relayBidirectional(clientConn net.Conn, upstream net.Conn, onTx func(int), onRx func(int), logf func(string, ...any), target string) {
	var closeOnce sync.Once
	shutdown := func() {
		closeOnce.Do(func() {
			_ = upstream.Close()
			_ = clientConn.Close()
		})
	}

	var wg sync.WaitGroup
	var clientToUpstreamFirst atomic.Bool
	var upstreamToClientFirst atomic.Bool
	runCopy := func(label string, dst net.Conn, src net.Conn, onWrite func(int)) {
		defer wg.Done()
		if logf != nil {
			logf("relay: %s", label)
		}
		cw := &countingWriter{writer: dst, onWrite: onWrite}
		n, err := io.Copy(cw, src)
		if masqueDebugEnabled() && target == "ipwho.is:443" {
			first := &clientToUpstreamFirst
			if label == "upstream -> client" {
				first = &upstreamToClientFirst
			}
			if first.CompareAndSwap(false, true) {
				logf("masque debug: target=%s %s first-copy bytes=%d err=%v", target, label, n, err)
			}
			logf("masque debug: target=%s %s done bytes=%d err=%v", target, label, n, err)
		}
		if logf != nil {
			logf("relay: %s done", label)
		}
		shutdown()
	}

	wg.Add(2)
	go runCopy("client -> upstream", upstream, clientConn, onTx)
	go runCopy("upstream -> client", clientConn, upstream, onRx)
	wg.Wait()
}

func parseHTTPConnectTarget(host string) (hostPart, port string, err error) {
	hostPart, port, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostPart = host
		port = "443"
	}
	return hostPart, port, nil
}

func (h *httpProxyHandler) handleForward(w http.ResponseWriter, r *http.Request) {
	transport := h.manager.currentRoundTripper()
	if transport == nil {
		h.manager.logf("http proxy transport unavailable: target=%s", r.URL.String())
		http.Error(w, "proxy transport unavailable", http.StatusBadGateway)
		return
	}

	outReq := r.Clone(r.Context())
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}
	if strings.TrimSpace(outReq.URL.Host) == "" {
		h.manager.logf("http proxy missing target host: url=%s", r.URL.String())
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	var requestBodyCounter *countingReadCloser
	if outReq.Body != nil && outReq.Body != http.NoBody {
		requestBodyCounter = &countingReadCloser{ReadCloser: outReq.Body}
		outReq.Body = requestBodyCounter
	}

	started := time.Now()
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		h.manager.logf("http proxy forward upstream failed: target=%s host=%s err=%v", outReq.URL.String(), outReq.URL.Host, err)
		http.Error(w, "forward upstream failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	latency := time.Since(started)
	if latency <= 0 {
		latency = time.Nanosecond
	}
	h.manager.RecordHandshakeLatency(latency)

	removeHopByHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	n, copyErr := io.Copy(w, resp.Body)
	h.manager.AddRxBytes(int(n))
	if requestBodyCounter != nil {
		h.manager.AddTxBytes(requestBodyCounter.count)
	}
	if copyErr != nil {
		return
	}
}

func (m *HTTPProxyManager) currentHTTPDialer() HTTPStreamDialer {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dialer != nil {
		return m.dialer
	}
	return &net.Dialer{Timeout: m.cfg.ConnectTimeout}
}

func (m *HTTPProxyManager) currentStreamManager() *ConnectStreamManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamManager
}

func (m *HTTPProxyManager) currentRoundTripper() http.RoundTripper {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transport != nil {
		return m.transport
	}
	dialer := m.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: m.cfg.ConnectTimeout}
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, key := range []string{
		"Proxy-Connection",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Connection",
		"Keep-Alive",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(key)
	}
}
