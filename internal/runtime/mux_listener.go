package runtime

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
)

var errUnsupportedProxyProtocol = errors.New("unsupported proxy protocol")

type proxyProtocol uint8

const (
	proxyProtocolUnknown proxyProtocol = iota
	proxyProtocolHTTP
	proxyProtocolSOCKS5
)

type MuxListener struct {
	listener  net.Listener
	http      *chanListener
	socks5    *chanListener
	closeOnce sync.Once
	runWG     sync.WaitGroup
}

func ListenMux(address string) (*MuxListener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return NewMuxListener(listener)
}

func NewMuxListener(listener net.Listener) (*MuxListener, error) {
	if listener == nil {
		return nil, errors.New("listener is required")
	}
	m := &MuxListener{
		listener: listener,
		http:     newChanListener(listener.Addr()),
		socks5:   newChanListener(listener.Addr()),
	}
	m.runWG.Add(1)
	go m.acceptLoop()
	return m, nil
}

func (m *MuxListener) HTTPListener() net.Listener   { return m.http }
func (m *MuxListener) SOCKS5Listener() net.Listener { return m.socks5 }
func (m *MuxListener) Addr() net.Addr               { return m.listener.Addr() }
func (m *MuxListener) ListenAddress() string        { return m.listener.Addr().String() }

func (m *MuxListener) Close() error {
	m.closeOnce.Do(func() {
		_ = m.http.Close()
		_ = m.socks5.Close()
		_ = m.listener.Close()
	})
	m.runWG.Wait()
	return nil
}

func (m *MuxListener) acceptLoop() {
	defer m.runWG.Done()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		m.runWG.Add(1)
		go func() {
			defer m.runWG.Done()
			m.dispatch(conn)
		}()
	}
}

func (m *MuxListener) dispatch(conn net.Conn) {
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		_ = conn.Close()
		return
	}
	protocol, err := sniffProxyProtocol(first[0])
	if err != nil {
		_ = conn.Close()
		return
	}
	replayed := &prefixedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(first[:]), conn),
	}
	switch protocol {
	case proxyProtocolHTTP:
		if err := m.http.enqueue(replayed); err != nil {
			_ = replayed.Close()
		}
	case proxyProtocolSOCKS5:
		if err := m.socks5.enqueue(replayed); err != nil {
			_ = replayed.Close()
		}
	default:
		_ = replayed.Close()
	}
}

func sniffProxyProtocol(first byte) (proxyProtocol, error) {
	if first == 0x05 {
		return proxyProtocolSOCKS5, nil
	}
	if first >= 'A' && first <= 'Z' {
		return proxyProtocolHTTP, nil
	}
	if first >= 'a' && first <= 'z' {
		return proxyProtocolHTTP, nil
	}
	return proxyProtocolUnknown, errUnsupportedProxyProtocol
}

type prefixedConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

type chanListener struct {
	addr      net.Addr
	connCh    chan net.Conn
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{
		addr:    addr,
		connCh:  make(chan net.Conn),
		closeCh: make(chan struct{}),
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case <-l.closeCh:
		return nil, net.ErrClosed
	case conn := <-l.connCh:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *chanListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

func (l *chanListener) enqueue(conn net.Conn) error {
	select {
	case <-l.closeCh:
		return net.ErrClosed
	case l.connCh <- conn:
		return nil
	}
}
