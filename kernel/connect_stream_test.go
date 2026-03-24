package kernel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/skye-z/amz/config"
)

type stubAddr string

func (a stubAddr) Network() string { return "test" }
func (a stubAddr) String() string  { return string(a) }

type fakeRequestStream struct {
	readData        []byte
	writeData       []byte
	response        *http.Response
	sendErr         error
	readResponseErr error
	readErr         error
	writeErr        error
	closeErr        error
	deadline        time.Time
	readDeadline    time.Time
	writeDeadline   time.Time
	closed          bool
	request         *http.Request
	readOffset      int
	localAddr       net.Addr
	remoteAddr      net.Addr
	bodyClosed      bool
}

func (s *fakeRequestStream) SendRequestHeader(req *http.Request) error {
	s.request = req
	return s.sendErr
}

func (s *fakeRequestStream) ReadResponse() (*http.Response, error) {
	if s.readResponseErr != nil {
		return nil, s.readResponseErr
	}
	if s.response == nil {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	if s.response.Body != nil {
		s.response.Body = &trackingReadCloser{ReadCloser: s.response.Body, closed: &s.bodyClosed}
	}
	return s.response, nil
}

func (s *fakeRequestStream) Read(b []byte) (int, error) {
	if s.readErr != nil {
		return 0, s.readErr
	}
	if s.readOffset >= len(s.readData) {
		return 0, io.EOF
	}
	n := copy(b, s.readData[s.readOffset:])
	s.readOffset += n
	return n, nil
}

func (s *fakeRequestStream) Write(b []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.writeData = append(s.writeData, b...)
	return len(b), nil
}

func (s *fakeRequestStream) Close() error {
	s.closed = true
	return s.closeErr
}

func (s *fakeRequestStream) SetDeadline(t time.Time) error {
	s.deadline = t
	return nil
}

func (s *fakeRequestStream) SetReadDeadline(t time.Time) error {
	s.readDeadline = t
	return nil
}

func (s *fakeRequestStream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline = t
	return nil
}

func (s *fakeRequestStream) LocalAddr() net.Addr {
	if s.localAddr != nil {
		return s.localAddr
	}
	return stubAddr("local")
}

func (s *fakeRequestStream) RemoteAddr() net.Addr {
	if s.remoteAddr != nil {
		return s.remoteAddr
	}
	return stubAddr("remote")
}

type fakeRequestConn struct {
	stream    h3RequestStream
	openErr   error
	openedCtx context.Context
	opened    bool
}

func (c *fakeRequestConn) OpenRequestStream(ctx context.Context) (h3RequestStream, error) {
	c.opened = true
	c.openedCtx = ctx
	if c.openErr != nil {
		return nil, c.openErr
	}
	return c.stream, nil
}

type fakeBoundH3Client struct {
	requestConn h3RequestConn
	closeErr    error
	awaitErr    error
}

type trackingReadCloser struct {
	io.ReadCloser
	closed *bool
}

func (r *trackingReadCloser) Close() error {
	if r.closed != nil {
		*r.closed = true
	}
	return r.ReadCloser.Close()
}

func (c *fakeBoundH3Client) Close() error { return c.closeErr }

func (c *fakeBoundH3Client) AwaitSettings(ctx context.Context, requireDatagrams, requireExtendedConnect bool) error {
	return c.awaitErr
}

func (c *fakeBoundH3Client) Raw() *http3.ClientConn { return nil }

func (c *fakeBoundH3Client) RequestConn() h3RequestConn { return c.requestConn }

func TestBuildConnectStreamOptions(t *testing.T) {
	h3 := HTTP3Options{
		Authority:       "162.159.197.1:443",
		EnableDatagrams: true,
	}

	opts := BuildConnectStreamOptions(h3, "example.com", "443")

	if opts.Authority != "162.159.197.1:443" {
		t.Errorf("expected authority %q, got %q", "162.159.197.1:443", opts.Authority)
	}
	if opts.TargetHost != "example.com" {
		t.Errorf("expected target host %q, got %q", "example.com", opts.TargetHost)
	}
	if opts.TargetPort != "443" {
		t.Errorf("expected target port %q, got %q", "443", opts.TargetPort)
	}
	if opts.Protocol != ProtocolConnectStream {
		t.Errorf("expected protocol %q, got %q", ProtocolConnectStream, opts.Protocol)
	}
}

func TestConnectStreamManager_StateTransitions(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	snapshot := mgr.Snapshot()
	if snapshot.State != StreamStateIdle {
		t.Errorf("expected state %q, got %q", StreamStateIdle, snapshot.State)
	}

	mgr.SetReady()
	snapshot = mgr.Snapshot()
	if snapshot.State != StreamStateReady {
		t.Errorf("expected state %q, got %q", StreamStateReady, snapshot.State)
	}

	if err := mgr.Close(); err != nil {
		t.Errorf("failed to close: %v", err)
	}
	snapshot = mgr.Snapshot()
	if snapshot.State != StreamStateIdle {
		t.Errorf("expected state %q, got %q", StreamStateIdle, snapshot.State)
	}
}

func TestConnectStreamManager_Stats(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	mgr.RecordHandshakeLatency(100 * time.Millisecond)
	mgr.AddTxBytes(1024)
	mgr.AddRxBytes(2048)

	stats := mgr.Stats()
	if stats.HandshakeLatency <= 0 {
		t.Error("expected positive handshake latency")
	}
	if stats.TxBytes != 1024 {
		t.Errorf("expected tx bytes %d, got %d", 1024, stats.TxBytes)
	}
	if stats.RxBytes != 2048 {
		t.Errorf("expected rx bytes %d, got %d", 2048, stats.RxBytes)
	}
}

func TestParseConnectTarget(t *testing.T) {
	tests := []struct {
		url      string
		wantHost string
		wantPort string
	}{
		{"example.com:443", "example.com", "443"},
		{"https://example.com:8443", "example.com", "8443"},
		{"http://example.com", "example.com", "443"},
		{"example.com", "example.com", "443"},
		{"192.168.1.1:8080", "192.168.1.1", "8080"},
	}

	for _, tt := range tests {
		host, port, err := parseConnectTarget(tt.url)
		if err != nil {
			t.Errorf("parseConnectTarget(%q) error: %v", tt.url, err)
			continue
		}
		if host != tt.wantHost {
			t.Errorf("parseConnectTarget(%q) host = %q, want %q", tt.url, host, tt.wantHost)
		}
		if port != tt.wantPort {
			t.Errorf("parseConnectTarget(%q) port = %q, want %q", tt.url, port, tt.wantPort)
		}
	}
}

func TestActiveStream_ReadWrite(t *testing.T) {
	stream := &activeStream{
		info: StreamInfo{
			RemoteAddr: "example.com:443",
			Protocol:   ProtocolConnectStream,
		},
		local:  "127.0.0.1:40000",
		remote: "example.com:443",
	}

	if stream.conn != nil {
		t.Error("expected nil conn for unconnected stream")
	}

	_, err := stream.Read([]byte{})
	if err == nil {
		t.Error("expected error when reading from unconnected stream")
	}

	_, err = stream.Write([]byte("test"))
	if err == nil {
		t.Error("expected error when writing to unconnected stream")
	}
}

func TestConnectStreamManager_OpenStream_NotReady(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = mgr.OpenStream(ctx, "example.com", "443")
	if err == nil {
		t.Error("expected error when opening stream in idle state")
	}
}

func TestConnectStreamManager_StreamEndpoint_NotFound(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	mgr.SetReady()

	endpoint := mgr.StreamEndpoint("nonexistent.example.com", "443")
	if endpoint != nil {
		t.Error("expected nil endpoint for nonexistent stream")
	}
}

func TestConnectStreamManager_CloseStream_NotFound(t *testing.T) {
	cfg := config.KernelConfig{
		Mode:     config.ModeSOCKS,
		Endpoint: "162.159.197.1:443",
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()

	mgr, err := NewConnectStreamManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	err = mgr.CloseStream("nonexistent.example.com", "443")
	if err != nil {
		t.Errorf("expected no error when closing nonexistent stream: %v", err)
	}
}

func TestConnectStreamDialerUsesSingleRequestStream(t *testing.T) {
	stream := &fakeRequestStream{
		readData:   []byte("server-bytes"),
		response:   &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))},
		localAddr:  stubAddr("127.0.0.1:4444"),
		remoteAddr: stubAddr("example.com:443"),
	}
	client := &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}

	conn, rsp, latency, err := realStreamDialer{}.DialStream(
		context.Background(),
		client,
		QUICOptions{Endpoint: "127.0.0.1:4444"},
		HTTP3Options{Authority: "masque.example:443"},
		ConnectStreamOptions{TargetHost: "example.com", TargetPort: "443", Protocol: ProtocolConnectStream},
	)
	if err != nil {
		t.Fatalf("DialStream returned error: %v", err)
	}
	if rsp == nil || rsp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 response, got %#v", rsp)
	}
	if latency < 0 {
		t.Fatalf("expected non-negative latency, got %s", latency)
	}
	if stream.request == nil {
		t.Fatal("expected CONNECT request to be sent on opened request stream")
	}
	if stream.request.Method != http.MethodConnect {
		t.Fatalf("expected CONNECT method, got %q", stream.request.Method)
	}
	if got := stream.request.Host; got != "example.com:443" {
		t.Fatalf("expected request host %q, got %q", "example.com:443", got)
	}
	if got := stream.request.Header.Get("X-Masque-Protocol"); got != ProtocolConnectStream {
		t.Fatalf("expected masque protocol header %q, got %q", ProtocolConnectStream, got)
	}

	buf := make([]byte, len("server-bytes"))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if got := string(buf[:n]); got != "server-bytes" {
		t.Fatalf("expected read bytes %q, got %q", "server-bytes", got)
	}

	if _, err := conn.Write([]byte("client-bytes")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if got := string(stream.writeData); got != "client-bytes" {
		t.Fatalf("expected written bytes %q, got %q", "client-bytes", got)
	}
	if stream.bodyClosed {
		t.Fatal("expected successful CONNECT response body to remain open for stream relay")
	}
	if got := conn.LocalAddr().String(); got != "127.0.0.1:4444" {
		t.Fatalf("expected local addr %q, got %q", "127.0.0.1:4444", got)
	}
	if got := conn.RemoteAddr().String(); got != "example.com:443" {
		t.Fatalf("expected remote addr %q, got %q", "example.com:443", got)
	}

	deadline := time.Now().Add(time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline returned error: %v", err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline returned error: %v", err)
	}
	if !stream.deadline.Equal(deadline) || !stream.readDeadline.Equal(deadline) || !stream.writeDeadline.Equal(deadline) {
		t.Fatal("expected deadlines to be forwarded to request stream")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if !stream.closed {
		t.Fatal("expected closing conn to close request stream")
	}
}

func TestConnectStreamDialerReturnsErrorForNon2xxResponse(t *testing.T) {
	stream := &fakeRequestStream{
		response: &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       io.NopCloser(strings.NewReader("connect rejected")),
		},
	}

	conn, rsp, latency, err := realStreamDialer{}.DialStream(
		context.Background(),
		&fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}},
		QUICOptions{Endpoint: "127.0.0.1:4444"},
		HTTP3Options{Authority: "masque.example:443"},
		ConnectStreamOptions{TargetHost: "example.com", TargetPort: "443", Protocol: ProtocolConnectStream},
	)
	if err == nil {
		t.Fatal("expected error for non-2xx CONNECT response")
	}
	if conn != nil {
		t.Fatal("expected nil conn on non-2xx response")
	}
	if rsp == nil || rsp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 response, got %#v", rsp)
	}
	if latency != 0 {
		t.Fatalf("expected zero latency on error path, got %s", latency)
	}
	if !stream.closed {
		t.Fatal("expected request stream to close on non-2xx response")
	}
	if !strings.Contains(err.Error(), "status=502") {
		t.Fatalf("expected error to include status code, got %v", err)
	}
	if !strings.Contains(err.Error(), "connect rejected") {
		t.Fatalf("expected error to include response body, got %v", err)
	}
}

func TestHTTP3StreamConnWithoutStreamFailsCleanly(t *testing.T) {
	conn := &http3StreamConn{}

	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF read error, got %v", err)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF write error, got %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("expected nil close error, got %v", err)
	}
	if conn.LocalAddr() == nil {
		t.Fatal("expected local addr fallback")
	}
	if conn.RemoteAddr() == nil {
		t.Fatal("expected remote addr fallback")
	}
}
