package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
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

type Snapshot struct {
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

type UDPAssociateRelay interface {
	Exchange(ctx context.Context, req UDPAssociateRequest) (UDPAssociateResponse, error)
}

type ConnectStreamOpener interface {
	OpenStream(context.Context, string, string) (net.Conn, error)
}

type Manager struct {
	mu            sync.Mutex
	cfg           config.KernelConfig
	state         string
	stats         types.Stats
	listen        string
	listener      net.Listener
	udpPacketConn net.PacketConn
	runCancel     context.CancelFunc
	runWG         sync.WaitGroup
	udpRelay      UDPAssociateRelay
	associations  map[string]*udpAssociation
	streamManager ConnectStreamOpener
}

type udpAssociation struct {
	clientHost string
	conn       net.Conn
	udpAddr    net.Addr
}

func New(cfg *config.KernelConfig) (*Manager, error) {
	clone, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: clone, state: types.StateIdle, listen: clone.SOCKS.ListenAddress}, nil
}

func (m *Manager) ListenAddress() string { m.mu.Lock(); defer m.mu.Unlock(); return m.listen }
func (m *Manager) Close() error          { return m.Stop(context.Background()) }
func (m *Manager) State() string         { m.mu.Lock(); defer m.mu.Unlock(); return m.state }
func (m *Manager) Stats() types.Stats    { m.mu.Lock(); defer m.mu.Unlock(); return m.stats }

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{ListenAddress: m.listen, Username: m.cfg.SOCKS.Username, EnableUDP: m.cfg.SOCKS.EnableUDP}
}

func (m *Manager) RecordHandshakeLatency(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.HandshakeLatency = latency
}
func (m *Manager) AddTxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.TxBytes += n
}
func (m *Manager) AddRxBytes(n int) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.RxBytes += n
}
func (m *Manager) AddReconnect() { m.mu.Lock(); defer m.mu.Unlock(); m.stats.ReconnectCount++ }
func (m *Manager) SetUDPAssociateRelay(relay UDPAssociateRelay) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.udpRelay = relay
}
func (m *Manager) SetStreamManager(mgr ConnectStreamOpener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamManager = mgr
}

func (m *Manager) Start(ctx context.Context) error {
	return m.start(ctx, nil)
}

func (m *Manager) StartWithListener(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	return m.start(ctx, listener)
}

func (m *Manager) start(ctx context.Context, provided net.Listener) error {
	m.mu.Lock()
	if m.state == types.StateStopped {
		m.mu.Unlock()
		return errors.New("proxy manager already stopped")
	}
	if m.state == types.StateRunning {
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
	runCtx, cancel := context.WithCancel(context.Background())
	m.listener = ln
	m.udpPacketConn = packetConn
	m.listen = actualListen
	m.runCancel = cancel
	m.state = types.StateRunning
	m.stats.StartCount++
	if m.associations == nil {
		m.associations = make(map[string]*udpAssociation)
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

func (m *Manager) Stop(context.Context) error {
	m.mu.Lock()
	if m.state == types.StateStopped {
		m.mu.Unlock()
		return nil
	}
	listener := m.listener
	packetConn := m.udpPacketConn
	cancel := m.runCancel
	associations := make([]*udpAssociation, 0, len(m.associations))
	for _, assoc := range m.associations {
		associations = append(associations, assoc)
	}
	m.listener = nil
	m.udpPacketConn = nil
	m.runCancel = nil
	m.associations = nil
	m.state = types.StateStopped
	m.stats.StopCount++
	m.logf("socks manager stop: listen=%s endpoint=%s", m.listen, m.cfg.Endpoint)
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listener != nil {
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
	m.runWG.Wait()
	return nil
}

func (m *Manager) acceptLoop(ctx context.Context) {
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
		m.runWG.Add(1)
		go func() { defer m.runWG.Done(); m.handleConnection(ctx, conn) }()
	}
}

func (m *Manager) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()
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

func (m *Manager) handleConnect(ctx context.Context, clientConn net.Conn, targetAddr string) error {
	m.mu.Lock()
	streamMgr := m.streamManager
	m.mu.Unlock()
	if streamMgr == nil {
		_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
		return fmt.Errorf("stream manager not configured")
	}
	host, port, err := parseSOCKSTargetAddress(targetAddr)
	if err != nil {
		_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
		return err
	}
	remoteConn, err := streamMgr.OpenStream(ctx, host, port)
	if err != nil {
		_ = writeSOCKSReply(clientConn, socksReplyGeneralFailure, clientConn.LocalAddr().String())
		return err
	}
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

func (m *Manager) negotiate(conn net.Conn) error {
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

func (m *Manager) handleUserPassAuth(conn net.Conn) error {
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

func (m *Manager) handleUDPAssociate(ctx context.Context, conn net.Conn) error {
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

func (m *Manager) udpLoop(ctx context.Context) {
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

func (m *Manager) logf(format string, args ...any) {
	if m.cfg.Logger == nil {
		return
	}
	m.cfg.Logger.Printf(types.SanitizeText(format), sanitizeArgs(args)...)
}

func normalizeConfig(cfg *config.KernelConfig) (config.KernelConfig, error) {
	if cfg == nil {
		return config.KernelConfig{}, errors.New("kernel config is required")
	}
	clone := *cfg
	clone.Mode = config.ModeSOCKS
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return config.KernelConfig{}, err
	}
	return clone, nil
}

func sanitizeArgs(args []any) []any {
	if len(args) == 0 {
		return nil
	}
	masked := make([]any, len(args))
	for i, arg := range args {
		if text, ok := arg.(string); ok {
			masked[i] = types.SanitizeText(text)
			continue
		}
		if err, ok := arg.(error); ok {
			masked[i] = types.SanitizeError(err)
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

type countingWriter struct {
	writer  io.Writer
	onWrite func(int)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if n > 0 && c.onWrite != nil {
		c.onWrite(n)
	}
	return n, err
}
