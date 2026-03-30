package session

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/testkit"
)

const (
	preparedStreamTestTargetHost = testkit.TestDomain
	preparedStreamTestTargetPort = "443"
)

func TestPreparedConnectStreamOpenerPreparesBeforeOpen(t *testing.T) {
	t.Parallel()

	preparer := &stubStreamPreparer{}
	manager := &stubPreparedStreamManager{}
	opener := NewPreparedConnectStreamOpener(preparer, manager)

	conn, err := opener.OpenStream(context.Background(), preparedStreamTestTargetHost, preparedStreamTestTargetPort)
	if err != nil {
		t.Fatalf("expected open stream success, got %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil stream connection")
	}
	if !preparer.called {
		t.Fatal("expected PrepareStream to be called before OpenStream")
	}
	if !manager.called {
		t.Fatal("expected underlying stream manager to be called")
	}
	if manager.host != preparedStreamTestTargetHost || manager.port != preparedStreamTestTargetPort {
		t.Fatalf("unexpected target %s:%s", manager.host, manager.port)
	}
}

func TestPreparedConnectStreamOpenerReturnsPrepareError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("prepare failed")
	opener := NewPreparedConnectStreamOpener(&stubStreamPreparer{err: wantErr}, &stubPreparedStreamManager{})

	_, err := opener.OpenStream(context.Background(), preparedStreamTestTargetHost, preparedStreamTestTargetPort)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected prepare error %v, got %v", wantErr, err)
	}
}

func TestPreparedProxyStreamOpenerUsesPlainConnect(t *testing.T) {
	t.Parallel()

	stream := &fakeRequestStream{
		response: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody},
	}
	manager, err := NewConnectStreamManager(testConnectStreamConfig())
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	manager.h3conn = &fakeBoundH3Client{requestConn: &fakeRequestConn{stream: stream}}
	manager.SetReady()

	opener := NewPreparedProxyStreamOpener(nil, manager)
	conn, err := opener.OpenStream(context.Background(), preparedStreamTestTargetHost, preparedStreamTestTargetPort)
	if err != nil {
		t.Fatalf("expected proxy stream open success, got %v", err)
	}
	_ = conn.Close()

	if stream.request == nil {
		t.Fatal("expected CONNECT request to be sent")
	}
	if stream.request.Proto != "" {
		t.Fatalf("expected plain CONNECT without protocol token, got %q", stream.request.Proto)
	}
}

type stubStreamPreparer struct {
	called bool
	err    error
}

func (s *stubStreamPreparer) PrepareStream(context.Context) error {
	s.called = true
	return s.err
}

type stubPreparedStreamManager struct {
	called bool
	host   string
	port   string
}

func (s *stubPreparedStreamManager) OpenStream(_ context.Context, host, port string) (net.Conn, error) {
	s.called = true
	s.host = host
	s.port = port
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func testConnectStreamConfig() config.KernelConfig {
	cfg := config.KernelConfig{
		Mode:     config.ModeHTTP,
		Endpoint: testkit.WarpIPv4Legacy443,
		SNI:      "warp.cloudflare.com",
	}
	cfg.FillDefaults()
	return cfg
}
