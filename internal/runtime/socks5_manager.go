package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	internalconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/failure"
	"github.com/skye-z/amz/internal/observe"
)

const (
	socksVersion5               = 0x05
	socksAuthVersion            = 0x01
	socksMethodNoAuth           = 0x00
	socksMethodUserPass         = 0x02
	socksMethodNoAcceptable     = 0xFF
	socksCommandConnect         = 0x01
	socksCommandUDPAssociate    = 0x03
	socksReplySucceeded         = 0x00
	socksReplyGeneralFailure    = 0x01
	socksReplyCommandNotSup     = 0x07
	socksReplyAddressTypeNotSup = 0x08
	socksAtypIPv4               = 0x01
	socksAtypDomain             = 0x03
	socksAtypIPv6               = 0x04
)

type SOCKS5Snapshot struct {
	ListenAddress string
	Username      string
	EnableUDP     bool
}

type UDPAssociateRequest struct {
	TargetAddress string
	Payload       []byte
}

type UDPAssociateResponse struct {
	SourceAddress string
	Payload       []byte
}

type UDPAssociateExchanger interface {
	Exchange(ctx context.Context, req UDPAssociateRequest) (UDPAssociateResponse, error)
}

type SOCKS5ConnectStreamOpener interface {
	OpenStream(context.Context, string, string) (net.Conn, error)
}

type SOCKS5Manager struct {
	mu            sync.Mutex
	cfg           internalconfig.KernelConfig
	state         string
	stats         internalconfig.Stats
	listen        string
	listener      net.Listener
	listenerOwned bool
	udpPacketConn net.PacketConn
	runCancel     context.CancelFunc
	runWG         sync.WaitGroup
	udpRelay      UDPAssociateExchanger
	associations  map[string]*udpAssociation
	activeTCP     map[net.Conn]struct{}
	streamManager SOCKS5ConnectStreamOpener
	dialer        contextDialer
	failureReport func(failure.Event)
}

type udpAssociation struct {
	clientHost string
	conn       net.Conn
	udpAddr    net.Addr
}

func NewSOCKS5Manager(cfg *internalconfig.KernelConfig) (*SOCKS5Manager, error) {
	clone, err := normalizeSOCKS5Config(cfg)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Manager{cfg: clone, state: internalconfig.StateIdle, listen: clone.SOCKS.ListenAddress}, nil
}

func (m *SOCKS5Manager) ListenAddress() string { m.mu.Lock(); defer m.mu.Unlock(); return m.listen }
func (m *SOCKS5Manager) Close() error          { return m.Stop(context.Background()) }
func (m *SOCKS5Manager) State() string         { m.mu.Lock(); defer m.mu.Unlock(); return m.state }
func (m *SOCKS5Manager) Stats() internalconfig.Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

func (m *SOCKS5Manager) Snapshot() SOCKS5Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return SOCKS5Snapshot{ListenAddress: m.listen, Username: m.cfg.SOCKS.Username, EnableUDP: m.cfg.SOCKS.EnableUDP}
}

func (m *SOCKS5Manager) RecordHandshakeLatency(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.HandshakeLatency = latency
}

func (m *SOCKS5Manager) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.TxBytes += n
}

func (m *SOCKS5Manager) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.RxBytes += n
}

func (m *SOCKS5Manager) AddReconnect() { m.mu.Lock(); defer m.mu.Unlock(); m.stats.ReconnectCount++ }

func (m *SOCKS5Manager) SetUDPAssociateRelay(relay UDPAssociateExchanger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.udpRelay = relay
}

func (m *SOCKS5Manager) SetStreamManager(mgr SOCKS5ConnectStreamOpener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamManager = mgr
}

func (m *SOCKS5Manager) SetDialer(d contextDialer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialer = d
}

func (m *SOCKS5Manager) SetFailureReporter(reporter func(failure.Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureReport = reporter
}

func (m *SOCKS5Manager) Start(ctx context.Context) error { return m.start(ctx, nil) }

func (m *SOCKS5Manager) StartWithListener(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	return m.start(ctx, listener)
}

func (m *SOCKS5Manager) start(ctx context.Context, provided net.Listener) error {
	m.mu.Lock()
	if m.state == internalconfig.StateStopped {
		m.mu.Unlock()
		return errors.New("proxy manager already stopped")
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
			return fmt.Errorf("listen socks tcp: %w", err)
		}
	}
	actualListen := ln.Addr().String()
	var packetConn net.PacketConn
	if m.cfg.SOCKS.EnableUDP {
		host, _, splitErr := net.SplitHostPort(actualListen)
		if splitErr != nil {
			_ = ln.Close()
			m.mu.Unlock()
			return fmt.Errorf("split socks listen host: %w", splitErr)
		}
		packetConn, err = net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			_ = ln.Close()
			m.mu.Unlock()
			return fmt.Errorf("listen socks udp: %w", err)
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.listener = ln
	m.listenerOwned = provided == nil
	m.udpPacketConn = packetConn
	m.listen = actualListen
	m.runCancel = cancel
	m.state = internalconfig.StateRunning
	m.stats.StartCount++
	if m.associations == nil {
		m.associations = make(map[string]*udpAssociation)
	}
	if m.activeTCP == nil {
		m.activeTCP = make(map[net.Conn]struct{})
	}
	m.logf("socks manager start: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.runWG.Add(1)
	go m.acceptLoop(runCtx)
	if packetConn != nil {
		m.runWG.Add(1)
		go m.udpLoop(runCtx)
	}
	m.mu.Unlock()
	return nil
}

func (m *SOCKS5Manager) Stop(context.Context) error {
	m.mu.Lock()
	if m.state == internalconfig.StateStopped {
		m.mu.Unlock()
		return nil
	}
	listener := m.listener
	listenerOwned := m.listenerOwned
	packetConn := m.udpPacketConn
	cancel := m.runCancel
	associations := make([]*udpAssociation, 0, len(m.associations))
	for _, assoc := range m.associations {
		associations = append(associations, assoc)
	}
	activeTCP := make([]net.Conn, 0, len(m.activeTCP))
	for conn := range m.activeTCP {
		activeTCP = append(activeTCP, conn)
	}
	m.listener = nil
	m.listenerOwned = false
	m.udpPacketConn = nil
	m.runCancel = nil
	m.associations = nil
	m.activeTCP = nil
	m.state = internalconfig.StateStopped
	m.stats.StopCount++
	m.logf("socks manager stop: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listenerOwned && listener != nil {
		_ = listener.Close()
	}
	if packetConn != nil {
		_ = packetConn.Close()
	}
	for _, assoc := range associations {
		if assoc != nil && assoc.conn != nil {
			_ = assoc.conn.Close()
		}
	}
	for _, conn := range activeTCP {
		if conn != nil {
			_ = conn.Close()
		}
	}
	m.runWG.Wait()
	return nil
}

func (m *SOCKS5Manager) acceptLoop(ctx context.Context) {
	defer m.runWG.Done()
	for {
		m.mu.Lock()
		listener := m.listener
		m.mu.Unlock()
		if listener == nil {
			return
		}
		conn, err := listener.Accept()
		if err != nil {
			if context.Cause(ctx) != nil || isClosedNetworkError(err) {
				return
			}
			continue
		}
		m.trackActiveTCPConn(conn)
		m.runWG.Add(1)
		go func() { defer m.runWG.Done(); m.handleConnection(ctx, conn) }()
	}
}

func (m *SOCKS5Manager) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	defer m.untrackActiveTCPConn(conn)
	started := time.Now()
	if err := m.negotiate(conn); err != nil {
		return
	}
	latency := time.Since(started)
	if latency <= 0 {
		latency = time.Nanosecond
	}
	m.RecordHandshakeLatency(latency)
	targetAddr, command, err := readSOCKSRequest(conn)
	if err != nil {
		return
	}
	switch command {
	case socksCommandConnect:
		if err := m.handleConnect(ctx, conn, targetAddr); err != nil {
			return
		}
	case socksCommandUDPAssociate:
		if err := m.handleUDPAssociate(ctx, conn); err != nil {
			return
		}
	default:
		_ = writeSOCKSReply(conn, socksReplyCommandNotSup, conn.LocalAddr().String())
		return
	}
}

func (m *SOCKS5Manager) handleConnect(ctx context.Context, clientConn net.Conn, targetAddr string) error {
	m.mu.Lock()
	streamMgr := m.streamManager
	dialer := m.dialer
	m.mu.Unlock()

	var remoteConn net.Conn
	var err error

	if dialer != nil {
		// Use direct packet-stack dialer (resolves hostname first)
		host, port, parseErr := parseSOCKSTargetAddress(targetAddr)
		if parseErr != nil {
			_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
			return parseErr
		}
		address := net.JoinHostPort(host, port)
		remoteConn, err = dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			m.reportFailure("connect-upstream", err)
			if retriedConn, retriedErr, retried := m.retryConnectOnce(ctx, "connect-upstream", targetAddr, err); retried {
				if retriedErr == nil {
					remoteConn = retriedConn
					goto relay
				}
			}
			_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
			return err
		}
	} else if streamMgr != nil {
		host, port, parseErr := parseSOCKSTargetAddress(targetAddr)
		if parseErr != nil {
			_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
			return parseErr
		}
		remoteConn, err = streamMgr.OpenStream(ctx, host, port)
		if err != nil {
			m.reportFailure("connect-stream", err)
			if retriedConn, retriedErr, retried := m.retryConnectOnce(ctx, "connect-stream", targetAddr, err); retried {
				if retriedErr == nil {
					remoteConn = retriedConn
					goto relay
				}
			}
			_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
			return err
		}
	} else {
		_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
		return fmt.Errorf("no dialer or stream manager configured")
	}
relay:
	defer remoteConn.Close()
	if err := writeSOCKSReply(clientConn, socksReplySucceeded, remoteConn.LocalAddr().String()); err != nil {
		return err
	}
	errCh := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() { closeOnce.Do(func() { _ = remoteConn.Close(); _ = clientConn.Close() }) }
	go func() {
		_, err := io.Copy(&countingWriter{writer: remoteConn, onWrite: m.AddTxBytes}, clientConn)
		closeBoth()
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(&countingWriter{writer: clientConn, onWrite: m.AddRxBytes}, remoteConn)
		closeBoth()
		errCh <- err
	}()
	<-errCh
	closeBoth()
	return nil
}

func parseSOCKSTargetAddress(addr string) (host, port string, err error) {
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return "", "", splitErr
	}
	return host, port, nil
}

func (m *SOCKS5Manager) negotiate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("unsupported socks version: %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	username := m.cfg.SOCKS.Username
	password := m.cfg.SOCKS.Password
	if username == "" && password == "" {
		_, err := conn.Write([]byte{socksVersion5, socksMethodNoAuth})
		return err
	}
	for _, method := range methods {
		if method == socksMethodUserPass {
			if _, err := conn.Write([]byte{socksVersion5, socksMethodUserPass}); err != nil {
				return err
			}
			return m.handleUserPassAuth(conn)
		}
	}
	_, _ = conn.Write([]byte{socksVersion5, socksMethodNoAcceptable})
	return fmt.Errorf("no acceptable auth method")
}

func (m *SOCKS5Manager) handleUserPassAuth(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksAuthVersion {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}
	user := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	passLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return err
	}
	pass := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	if string(user) != m.cfg.SOCKS.Username || string(pass) != m.cfg.SOCKS.Password {
		_, _ = conn.Write([]byte{socksAuthVersion, 0x01})
		return fmt.Errorf("invalid username or password")
	}
	_, err := conn.Write([]byte{socksAuthVersion, 0x00})
	return err
}

func (m *SOCKS5Manager) reportFailure(operation string, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	reporter := m.failureReport
	endpoint := m.cfg.Endpoint
	m.mu.Unlock()
	if reporter != nil {
		reporter(failure.Event{
			Component: failure.ComponentSOCKS5,
			Operation: operation,
			Endpoint:  endpoint,
			Err:       err,
		})
	}
}

func (m *SOCKS5Manager) currentEndpoint() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Endpoint
}

func (m *SOCKS5Manager) retryConnectOnce(ctx context.Context, operation, targetAddr string, cause error) (net.Conn, error, bool) {
	currentEndpoint := m.currentEndpoint()
	currentSignature := m.currentBackendSignature()
	decision := failure.Classify(failure.Event{
		Component: failure.ComponentSOCKS5,
		Operation: operation,
		Endpoint:  currentEndpoint,
		Err:       cause,
	})
	if decision.Action == failure.ActionIgnore {
		return nil, nil, false
	}
	if decision.Action == failure.ActionSwitchEndpoint {
		if !m.waitForBackendRefresh(ctx, currentEndpoint, currentSignature, 2*time.Second) {
			return nil, nil, false
		}
	}

	streamMgr := m.currentStreamManager()
	if streamMgr != nil {
		host, port, err := parseSOCKSTargetAddress(targetAddr)
		if err != nil {
			return nil, err, true
		}
		conn, err := streamMgr.OpenStream(ctx, host, port)
		if err == nil {
			return conn, nil, true
		}
		cause = err
	}

	dialer := m.currentDialer()
	if dialer == nil {
		return nil, cause, true
	}
	host, port, err := parseSOCKSTargetAddress(targetAddr)
	if err != nil {
		return nil, err, true
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	return conn, err, true
}

func (m *SOCKS5Manager) currentBackendSignature() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("%p|%p|%s", m.dialer, m.streamManager, m.cfg.Endpoint)
}

func (m *SOCKS5Manager) waitForBackendRefresh(ctx context.Context, currentEndpoint, currentSignature string, timeout time.Duration) bool {
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
func (m *SOCKS5Manager) waitForEndpointChange(ctx context.Context, current string, timeout time.Duration) bool {
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

func (m *SOCKS5Manager) currentStreamManager() SOCKS5ConnectStreamOpener {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamManager
}

func (m *SOCKS5Manager) currentDialer() contextDialer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dialer
}

func (m *SOCKS5Manager) swapBackendFrom(other *SOCKS5Manager) {
	if m == nil || other == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Endpoint = other.cfg.Endpoint
	m.udpRelay = other.udpRelay
	m.streamManager = other.streamManager
	m.dialer = other.dialer
	m.failureReport = other.failureReport
}

func (m *SOCKS5Manager) trackActiveTCPConn(conn net.Conn) {
	if conn == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTCP == nil {
		m.activeTCP = make(map[net.Conn]struct{})
	}
	m.activeTCP[conn] = struct{}{}
}

func (m *SOCKS5Manager) untrackActiveTCPConn(conn net.Conn) {
	if conn == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeTCP == nil {
		return
	}
	delete(m.activeTCP, conn)
}

func (m *SOCKS5Manager) handleUDPAssociate(ctx context.Context, conn net.Conn) error {
	m.mu.Lock()
	packetConn := m.udpPacketConn
	relay := m.udpRelay
	m.mu.Unlock()
	if packetConn == nil || relay == nil {
		_ = writeSOCKSReply(conn, socksReplyCommandNotSup, conn.LocalAddr().String())
		return fmt.Errorf("udp associate unavailable")
	}
	if err := writeSOCKSReply(conn, socksReplySucceeded, packetConn.LocalAddr().String()); err != nil {
		return err
	}
	clientHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.associations[clientHost] = &udpAssociation{clientHost: clientHost, conn: conn, udpAddr: packetConn.LocalAddr()}
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.associations, clientHost); m.mu.Unlock() }()
	<-ctx.Done()
	return context.Cause(ctx)
}

func (m *SOCKS5Manager) udpLoop(ctx context.Context) {
	defer m.runWG.Done()
	buf := make([]byte, 65535)
	for {
		m.mu.Lock()
		packetConn := m.udpPacketConn
		relay := m.udpRelay
		m.mu.Unlock()
		if packetConn == nil || relay == nil {
			return
		}
		_ = packetConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := packetConn.ReadFrom(buf)
		if err != nil {
			if context.Cause(ctx) != nil || isClosedNetworkError(err) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		target, payload, err := parseSOCKSUDPDatagram(buf[:n])
		if err != nil {
			continue
		}
		exchangeCtx, cancel := context.WithTimeout(ctx, m.cfg.ConnectTimeout)
		response, err := relay.Exchange(exchangeCtx, UDPAssociateRequest{TargetAddress: target, Payload: payload})
		cancel()
		if err != nil {
			continue
		}
		m.AddTxBytes(len(payload))
		if len(response.Payload) == 0 {
			continue
		}
		packet, err := buildSOCKSUDPDatagram(response.SourceAddress, response.Payload)
		if err != nil {
			continue
		}
		if _, err := packetConn.WriteTo(packet, addr); err == nil {
			m.AddRxBytes(len(response.Payload))
		}
	}
}

func parseSOCKSUDPDatagram(packet []byte) (string, []byte, error) {
	if len(packet) < 4 {
		return "", nil, fmt.Errorf("udp packet too short")
	}
	if packet[2] != 0x00 {
		return "", nil, fmt.Errorf("fragmented udp packet not supported")
	}
	r := bytesReader(packet[3:])
	host, err := readAddress(&r)
	if err != nil {
		return "", nil, err
	}
	port, err := readPort(&r)
	if err != nil {
		return "", nil, err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), []byte(r), nil
}

func buildSOCKSUDPDatagram(sourceAddress string, payload []byte) ([]byte, error) {
	addr, err := encodeSOCKSAddress(sourceAddress)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, 3+len(addr)+len(payload))
	packet = append(packet, 0x00, 0x00, 0x00)
	packet = append(packet, addr...)
	packet = append(packet, payload...)
	return packet, nil
}

func writeSOCKSReply(conn net.Conn, rep byte, bindAddr string) error {
	addr, err := encodeSOCKSAddress(bindAddr)
	if err != nil {
		addr = []byte{socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	}
	reply := append([]byte{socksVersion5, rep, 0x00}, addr...)
	_, err = conn.Write(reply)
	return err
}

func readSOCKSRequest(conn net.Conn) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != socksVersion5 {
		return "", 0, fmt.Errorf("unsupported socks version: %d", header[0])
	}
	command := header[1]
	address, err := readAddressFromConn(conn, header[3])
	if err != nil {
		return "", 0, err
	}
	port, err := readPort(conn)
	if err != nil {
		return "", 0, err
	}
	return net.JoinHostPort(address, strconv.Itoa(port)), command, nil
}

func readAddressFromConn(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil
	case socksAtypDomain:
		size := make([]byte, 1)
		if _, err := io.ReadFull(r, size); err != nil {
			return "", err
		}
		host := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, host); err != nil {
			return "", err
		}
		return string(host), nil
	case socksAtypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func encodeSOCKSAddress(addr string) ([]byte, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portValue, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	if portValue < 0 || portValue > 65535 {
		return nil, fmt.Errorf("port out of range: %d", portValue)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			out := make([]byte, 1+4+2)
			out[0] = socksAtypIPv4
			copy(out[1:5], ipv4)
			binary.BigEndian.PutUint16(out[5:7], uint16(portValue))
			return out, nil
		}
		ipv6 := ip.To16()
		if ipv6 == nil {
			return nil, fmt.Errorf("invalid ip address %q", host)
		}
		out := make([]byte, 1+16+2)
		out[0] = socksAtypIPv6
		copy(out[1:17], ipv6)
		binary.BigEndian.PutUint16(out[17:19], uint16(portValue))
		return out, nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("domain name too long")
	}
	out := make([]byte, 1+1+len(host)+2)
	out[0] = socksAtypDomain
	out[1] = byte(len(host))
	copy(out[2:2+len(host)], host)
	binary.BigEndian.PutUint16(out[2+len(host):], uint16(portValue))
	return out, nil
}

func readPort(r io.Reader) (int, error) {
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(port)), nil
}

type bytesReader []byte

func (r *bytesReader) Read(dst []byte) (int, error) {
	if len(*r) == 0 {
		return 0, io.EOF
	}
	n := copy(dst, *r)
	*r = (*r)[n:]
	return n, nil
}

func (r *bytesReader) readByte() byte {
	if len(*r) == 0 {
		return 0
	}
	b := (*r)[0]
	*r = (*r)[1:]
	return b
}

func readAddress(r *bytesReader) (string, error) {
	atyp := r.readByte()
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypDomain:
		size := int(r.readByte())
		host := make([]byte, size)
		if _, err := io.ReadFull(r, host); err != nil {
			return "", err
		}
		return string(host), nil
	case socksAtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

func normalizeSOCKS5Config(cfg *internalconfig.KernelConfig) (internalconfig.KernelConfig, error) {
	if cfg == nil {
		return internalconfig.KernelConfig{}, errors.New("kernel config is required")
	}
	clone := *cfg
	clone.Mode = internalconfig.ModeSOCKS
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return internalconfig.KernelConfig{}, err
	}
	return clone, nil
}

func (m *SOCKS5Manager) logf(format string, args ...any) {
	if m.cfg.Logger == nil {
		return
	}
	m.cfg.Logger.Printf(observe.SanitizeText(format), sanitizeSOCKS5Args(args)...)
}

func sanitizeSOCKS5Args(args []any) []any {
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
