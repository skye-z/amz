package runtime

import (
	"bufio"
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
	"github.com/skye-z/amz/internal/failure"
	"github.com/skye-z/amz/internal/masque"
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
	listenerOwned bool
	server        *http.Server
	runWG         sync.WaitGroup
	dialer        HTTPStreamDialer
	transport     http.RoundTripper
	streamManager HTTPConnectStreamOpener
	failureReport func(failure.Event)
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

func (m *HTTPManager) SetFailureReporter(reporter func(failure.Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureReport = reporter
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
	m.listenerOwned = provided == nil
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
	listenerOwned := m.listenerOwned
	dialer := m.dialer
	m.server = nil
	m.listener = nil
	m.listenerOwned = false
	m.state = internalconfig.StateStopped
	m.stats.StopCount++
	m.logf("http proxy stop: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if listenerOwned && listener != nil {
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
		host, port, err := parseHTTPConnectTarget(r.Host)
		if err != nil {
			h.manager.logf("http proxy parse target failed: target=%s err=%v", r.Host, err)
			http.Error(w, "invalid target host", http.StatusBadRequest)
			return
		}
		started := time.Now()
		streamCtx, streamCancel := context.WithTimeout(r.Context(), h.manager.currentConnectTimeout())
		upstream, err := h.manager.openStreamWithTimeout(streamCtx, streamMgr, host, port)
		if err == nil {
			streamCancel()
			h.relayHTTPConnect(w, r, upstream, started, masque.ShouldDebugTarget(masqueDebugEnabled(), r.Host))
			return
		}
		streamCancel()
		h.manager.logf("http proxy connect stream failed: target=%s err=%v; fallback=dialer", r.Host, err)
		h.manager.reportFailure("connect-stream", err)
	}
	if dialer == nil {
		h.manager.logf("http proxy connect dialer unavailable: target=%s", r.Host)
		http.Error(w, "proxy dialer unavailable", http.StatusBadGateway)
		return
	}
	started := time.Now()
	previousEndpoint := h.manager.currentEndpoint()
	previousSignature := h.manager.currentBackendSignature()
	dialCtx, dialCancel := context.WithTimeout(r.Context(), h.manager.currentConnectTimeout())
	upstream, err := dialer.DialContext(dialCtx, "tcp", r.Host)
	if err == nil {
		dialCancel()
		h.relayHTTPConnect(w, r, upstream, started, false)
		return
	}
	dialCancel()
	if err != nil {
		h.manager.logf("http proxy connect upstream failed: target=%s err=%v", r.Host, err)
		h.manager.reportFailure("connect-upstream", err)
		retryCtx, retryCancel := context.WithTimeout(r.Context(), h.manager.currentConnectTimeout())
		if retriedUpstream, retriedErr, retried := h.manager.retryConnectOnce(retryCtx, "connect-upstream", r.Host, err, previousEndpoint, previousSignature); retried {
			if retriedErr == nil {
				retryCancel()
				h.relayHTTPConnect(w, r, retriedUpstream, started, false)
				return
			}
			retryCancel()
		}
		retryCancel()
		http.Error(w, "connect upstream failed", http.StatusBadGateway)
		return
	}
	h.relayHTTPConnect(w, r, upstream, started, false)
}

func (h *httpHandler) handleConnectViaStream(w http.ResponseWriter, r *http.Request, streamMgr HTTPConnectStreamOpener) {
	connectCtx, cancel := context.WithTimeout(r.Context(), h.manager.currentConnectTimeout())
	defer cancel()
	host, port, err := parseHTTPConnectTarget(r.Host)
	if err != nil {
		h.manager.logf("http proxy parse target failed: target=%s err=%v", r.Host, err)
		http.Error(w, "invalid target host", http.StatusBadRequest)
		return
	}
	debug := masque.ShouldDebugTarget(masqueDebugEnabled(), r.Host)
	started := time.Now()
	if debug {
		h.manager.logf("masque debug: connect target=%s opening stream", r.Host)
	}
	upstream, err := streamMgr.OpenStream(connectCtx, host, port)
	if err != nil {
		h.manager.logf("http proxy connect stream failed: target=%s err=%v", r.Host, err)
		http.Error(w, "connect stream failed", http.StatusBadGateway)
		return
	}
	h.relayHTTPConnect(w, r, upstream, started, debug)
}

func (h *httpHandler) relayHTTPConnect(w http.ResponseWriter, r *http.Request, upstream net.Conn, started time.Time, debug bool) {
	defer upstream.Close()
	h.recordConnectLatency(started)
	clientConn, rw, err := h.hijackHTTPConnect(w, r)
	if err != nil {
		return
	}
	defer clientConn.Close()
	if err := writeHTTPConnectEstablished(rw); err != nil {
		return
	}
	if err := h.forwardBufferedConnectBytes(rw, upstream, r.Host, debug); err != nil {
		return
	}
	relayBidirectional(clientConn, upstream, h.manager.AddTxBytes, h.manager.AddRxBytes, func(format string, args ...any) {
		if debug || !strings.HasPrefix(format, "masque debug:") {
			h.manager.logf(format, args...)
		}
	}, r.Host)
}

func (h *httpHandler) recordConnectLatency(started time.Time) {
	latency := time.Since(started)
	if latency <= 0 {
		latency = time.Nanosecond
	}
	h.manager.RecordHandshakeLatency(latency)
}

func (h *httpHandler) hijackHTTPConnect(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.manager.logf("http proxy hijack unsupported: target=%s", r.Host)
		http.Error(w, "proxy hijack unsupported", http.StatusInternalServerError)
		return nil, nil, errors.New("http hijacker unsupported")
	}
	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		h.manager.logf("http proxy hijack failed: target=%s err=%v", r.Host, err)
		http.Error(w, "proxy hijack failed", http.StatusInternalServerError)
		return nil, nil, err
	}
	return clientConn, rw, nil
}

func writeHTTPConnectEstablished(rw *bufio.ReadWriter) error {
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	return rw.Flush()
}

func (h *httpHandler) forwardBufferedConnectBytes(rw *bufio.ReadWriter, upstream net.Conn, target string, debug bool) error {
	buffered := rw.Reader.Buffered()
	if buffered <= 0 {
		return nil
	}
	peek, err := rw.Reader.Peek(buffered)
	if err != nil || len(peek) == 0 {
		return err
	}
	written, writeErr := upstream.Write(peek)
	h.manager.AddTxBytes(written)
	if debug {
		h.manager.logf("masque debug: connect target=%s pre-relay upstream write bytes=%d err=%v", target, written, writeErr)
	}
	if writeErr != nil {
		return writeErr
	}
	_, _ = rw.Reader.Discard(buffered)
	return nil
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
		if masque.ShouldDebugTarget(masqueDebugEnabled(), target) {
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

func (m *HTTPManager) openStreamWithTimeout(ctx context.Context, streamMgr HTTPConnectStreamOpener, host, port string) (net.Conn, error) {
	if streamMgr == nil {
		return nil, fmt.Errorf("stream manager is unavailable")
	}
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := streamMgr.OpenStream(ctx, host, port)
		select {
		case resultCh <- result{conn: conn, err: err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case res := <-resultCh:
		return res.conn, res.err
	}
}

func (m *HTTPManager) currentConnectTimeout() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.ConnectTimeout > 0 {
		return m.cfg.ConnectTimeout
	}
	return 10 * time.Second
}

func (m *HTTPManager) currentEndpoint() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Endpoint
}

func (m *HTTPManager) retryConnectOnce(ctx context.Context, operation, target string, cause error, previousEndpoint, previousSignature string) (net.Conn, error, bool) {
	currentEndpoint := strings.TrimSpace(previousEndpoint)
	if currentEndpoint == "" {
		currentEndpoint = m.currentEndpoint()
	}
	currentSignature := strings.TrimSpace(previousSignature)
	if currentSignature == "" {
		currentSignature = m.currentBackendSignature()
	}
	decision := failure.Classify(failure.Event{
		Component: failure.ComponentHTTP,
		Operation: operation,
		Endpoint:  currentEndpoint,
		Err:       cause,
	})
	if decision.Action == failure.ActionIgnore {
		return nil, nil, false
	}
	backendRefreshed := false
	if decision.Action == failure.ActionSwitchEndpoint {
		if !m.waitForBackendRefresh(ctx, currentEndpoint, currentSignature, m.currentConnectTimeout()) {
			return nil, nil, false
		}
		backendRefreshed = true
	}
	host, port, err := parseHTTPConnectTarget(target)
	if err != nil {
		return nil, err, true
	}
	streamMgr := m.currentStreamManager()
	if streamMgr != nil && (operation != "connect-stream" || backendRefreshed) {
		conn, err := m.openStreamWithTimeout(ctx, streamMgr, host, port)
		if err == nil {
			return conn, nil, true
		}
		cause = err
	}
	dialer := m.currentHTTPDialer()
	if dialer == nil {
		return nil, cause, true
	}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	return conn, err, true
}

func (m *HTTPManager) currentBackendSignature() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("%p|%p|%s", m.dialer, m.streamManager, m.cfg.Endpoint)
}

func (m *HTTPManager) waitForBackendRefresh(ctx context.Context, currentEndpoint, currentSignature string, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if endpoint := m.currentEndpoint(); endpoint != "" && endpoint != currentEndpoint {
			return true
		}
		if signature := m.currentBackendSignature(); signature != "" && signature != currentSignature {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}
func (m *HTTPManager) waitForEndpointChange(ctx context.Context, current string, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if endpoint := m.currentEndpoint(); endpoint != "" && endpoint != current {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (m *HTTPManager) reportFailure(operation string, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	reporter := m.failureReport
	endpoint := m.cfg.Endpoint
	m.mu.Unlock()
	if reporter != nil {
		reporter(failure.Event{
			Component: failure.ComponentHTTP,
			Operation: operation,
			Endpoint:  endpoint,
			Err:       err,
		})
	}
}

func (m *HTTPManager) swapBackendFrom(other *HTTPManager) {
	if m == nil || other == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Endpoint = other.cfg.Endpoint
	m.dialer = other.dialer
	m.transport = other.transport
	m.streamManager = other.streamManager
	m.failureReport = other.failureReport
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
