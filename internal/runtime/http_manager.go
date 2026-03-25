package runtime

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

	internalconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/observe"
)

var errHTTPProxyAlreadyStopped = errors.New("proxy manager already stopped")

type HTTPStreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type HTTPConnectStreamOpener interface {
	OpenStream(context.Context, string, string) (net.Conn, error)
}

type HTTPSnapshot struct {
	ListenAddress        string
	ReuseTunnelLifecycle bool
}

type HTTPManager struct {
	mu            sync.Mutex
	cfg           internalconfig.KernelConfig
	state         string
	stats         internalconfig.Stats
	listen        string
	listener      net.Listener
	server        *http.Server
	runWG         sync.WaitGroup
	dialer        HTTPStreamDialer
	transport     http.RoundTripper
	streamManager HTTPConnectStreamOpener
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

func NewHTTPManager(cfg internalconfig.KernelConfig) (*HTTPManager, error) {
	clone, err := normalizeHTTPConfig(&cfg)
	if err != nil {
		return nil, err
	}
	return &HTTPManager{cfg: clone, state: internalconfig.StateIdle, listen: clone.HTTP.ListenAddress}, nil
}

func (m *HTTPManager) ListenAddress() string       { m.mu.Lock(); defer m.mu.Unlock(); return m.listen }
func (m *HTTPManager) Close() error                { return m.Stop(context.Background()) }
func (m *HTTPManager) State() string               { m.mu.Lock(); defer m.mu.Unlock(); return m.state }
func (m *HTTPManager) Stats() internalconfig.Stats { m.mu.Lock(); defer m.mu.Unlock(); return m.stats }

func (m *HTTPManager) Snapshot() HTTPSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return HTTPSnapshot{ListenAddress: m.listen, ReuseTunnelLifecycle: true}
}

func (m *HTTPManager) RecordHandshakeLatency(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.HandshakeLatency = latency
}

func (m *HTTPManager) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.TxBytes += n
}

func (m *HTTPManager) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.RxBytes += n
}

func (m *HTTPManager) AddReconnect() { m.mu.Lock(); defer m.mu.Unlock(); m.stats.ReconnectCount++ }

func (m *HTTPManager) SetHTTPDialer(dialer HTTPStreamDialer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialer = dialer
	m.transport = nil
}

func (m *HTTPManager) SetStreamManager(mgr HTTPConnectStreamOpener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamManager = mgr
}

func (m *HTTPManager) SetHTTPRoundTripper(roundTripper http.RoundTripper) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transport = roundTripper
}

func (m *HTTPManager) Start(ctx context.Context) error { return m.start(ctx, nil) }

func (m *HTTPManager) StartWithListener(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	return m.start(ctx, listener)
}

func (m *HTTPManager) start(ctx context.Context, provided net.Listener) error {
	m.mu.Lock()
	if m.state == internalconfig.StateStopped {
		m.mu.Unlock()
		return errHTTPProxyAlreadyStopped
	}
	if m.state == internalconfig.StateRunning {
		m.mu.Unlock()
		return nil
	}
	if err := context.Cause(ctx); err != nil {
		m.mu.Unlock()
		return err
	}
	ln := provided
	var err error
	if ln == nil {
		ln, err = net.Listen("tcp", m.listen)
		if err != nil {
			m.mu.Unlock()
			return fmt.Errorf("listen http proxy: %w", err)
		}
	}
	server := &http.Server{Handler: &httpHandler{manager: m}, BaseContext: func(net.Listener) context.Context { return context.Background() }}
	m.listener = ln
	m.server = server
	m.listen = ln.Addr().String()
	m.state = internalconfig.StateRunning
	m.stats.StartCount++
	m.logf("http proxy start: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.runWG.Add(1)
	go func() {
		defer m.runWG.Done()
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !isClosedNetworkError(err) {
			m.mu.Lock()
			if m.state == internalconfig.StateRunning {
				m.state = internalconfig.StateStopped
				m.stats.StopCount++
			}
			m.mu.Unlock()
		}
	}()
	m.mu.Unlock()
	return nil
}

func (m *HTTPManager) Stop(context.Context) error {
	m.mu.Lock()
	if m.state == internalconfig.StateStopped {
		m.mu.Unlock()
		return nil
	}
	server := m.server
	listener := m.listener
	dialer := m.dialer
	m.server = nil
	m.listener = nil
	m.state = internalconfig.StateStopped
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

type httpHandler struct{ manager *HTTPManager }

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Method, http.MethodConnect) {
		h.handleConnect(w, r)
		return
	}
	h.handleForward(w, r)
}

func (h *httpHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
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

func (h *httpHandler) handleConnectViaStream(w http.ResponseWriter, r *http.Request, streamMgr HTTPConnectStreamOpener) {
	host, port, err := parseHTTPConnectTarget(r.Host)
	if err != nil {
		h.manager.logf("http proxy parse target failed: target=%s err=%v", r.Host, err)
		http.Error(w, "invalid target host", http.StatusBadRequest)
		return
	}
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
			if debug {
				h.manager.logf("masque debug: connect target=%s pre-relay upstream write bytes=%d err=%v", r.Host, written, writeErr)
			}
			if writeErr != nil {
				return
			}
			_, _ = rw.Reader.Discard(buffered)
		}
	}
	relayBidirectional(clientConn, upstream, h.manager.AddTxBytes, h.manager.AddRxBytes, func(format string, args ...any) {
		if debug || !strings.HasPrefix(format, "masque debug:") {
			h.manager.logf(format, args...)
		}
	}, r.Host)
}

func relayBidirectional(clientConn net.Conn, upstream net.Conn, onTx func(int), onRx func(int), logf func(string, ...any), target string) {
	var closeOnce sync.Once
	shutdown := func() { closeOnce.Do(func() { _ = upstream.Close(); _ = clientConn.Close() }) }
	var wg sync.WaitGroup
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

func (h *httpHandler) handleForward(w http.ResponseWriter, r *http.Request) {
	transport := h.manager.currentRoundTripper()
	if transport == nil {
		h.manager.logf("http proxy transport unavailable: target=%s", r.URL.String())
		http.Error(w, "proxy transport unavailable", http.StatusBadGateway)
		return
	}
	outbound := r.Clone(r.Context())
	removeHopByHopHeaders(outbound.Header)
	if outbound.URL.Scheme == "" {
		outbound.URL.Scheme = "http"
	}
	if outbound.URL.Host == "" {
		outbound.URL.Host = outbound.Host
	}
	var requestBodyCounter *countingReadCloser
	if outbound.Body != nil {
		requestBodyCounter = &countingReadCloser{ReadCloser: outbound.Body}
		outbound.Body = requestBodyCounter
	}
	resp, err := transport.RoundTrip(outbound)
	if err != nil {
		h.manager.logf("http proxy forward round trip failed: target=%s err=%v", outbound.URL.String(), err)
		http.Error(w, "forward proxy failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
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

func (m *HTTPManager) currentHTTPDialer() HTTPStreamDialer {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dialer != nil {
		return m.dialer
	}
	return &net.Dialer{Timeout: m.cfg.ConnectTimeout}
}

func (m *HTTPManager) currentStreamManager() HTTPConnectStreamOpener {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamManager
}

func (m *HTTPManager) currentRoundTripper() http.RoundTripper {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transport != nil {
		return m.transport
	}
	dialer := m.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: m.cfg.ConnectTimeout}
	}
	return &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, key := range []string{"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(key)
	}
}

func (m *HTTPManager) logf(format string, args ...any) {
	if m.cfg.Logger == nil {
		return
	}
	m.cfg.Logger.Printf(observe.SanitizeText(format), sanitizeHTTPArgs(args)...)
}

func normalizeHTTPConfig(cfg *internalconfig.KernelConfig) (internalconfig.KernelConfig, error) {
	if cfg == nil {
		return internalconfig.KernelConfig{}, errors.New("kernel config is required")
	}
	clone := *cfg
	clone.Mode = internalconfig.ModeHTTP
	if err := clone.Validate(); err != nil {
		return internalconfig.KernelConfig{}, err
	}
	return clone, nil
}

func sanitizeHTTPArgs(args []any) []any {
	if len(args) == 0 {
		return nil
	}
	masked := make([]any, len(args))
	for i, arg := range args {
		if text, ok := arg.(string); ok {
			masked[i] = observe.SanitizeText(text)
			continue
		}
		if err, ok := arg.(error); ok {
			masked[i] = observe.SanitizeError(err)
			continue
		}
		masked[i] = arg
	}
	return masked
}

func isClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "use of closed network connection")
}

var clientToUpstreamFirst atomic.Bool
var upstreamToClientFirst atomic.Bool

func masqueDebugEnabled() bool { return false }
