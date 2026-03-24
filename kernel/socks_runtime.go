package kernel

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

// 描述 UDP associate 请求。
type UDPAssociateRequest struct {
	TargetAddress string
	Payload       []byte
}

// 描述 UDP associate 返回报文。
type UDPAssociateResponse struct {
	SourceAddress string
	Payload       []byte
}

// 抽象 SOCKS5 UDP associate 数据面依赖的最小交换能力。
type UDPAssociateRelay interface {
	Exchange(ctx context.Context, req UDPAssociateRequest) (UDPAssociateResponse, error)
}

type udpAssociation struct {
	clientHost string
	conn       net.Conn
	udpAddr    net.Addr
}

// 注入 UDP associate 数据面依赖。
func (m *SOCKSManager) SetUDPAssociateRelay(relay UDPAssociateRelay) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.udpRelay = relay
}

// 注入 HTTP/3 CONNECT stream 依赖 (2026 L4 Proxy)。
func (m *SOCKSManager) SetStreamManager(mgr *ConnectStreamManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamManager = mgr
}

// 记录启动次数并切换到运行态，同时启动真实 SOCKS5 监听。
func (m *SOCKSManager) Start(ctx context.Context) error {
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
		return fmt.Errorf("listen socks tcp: %w", err)
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

// 记录停止次数并切换到停止态，同时关闭真实监听资源。
func (m *SOCKSManager) Stop(context.Context) error {
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

func (m *SOCKSManager) acceptLoop(ctx context.Context) {
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
		go func() {
			defer m.runWG.Done()
			m.handleConnection(ctx, conn)
		}()
	}
}

func (m *SOCKSManager) handleConnection(ctx context.Context, conn net.Conn) {
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

	command, targetAddr, err := readSOCKSRequest(conn)
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

func (m *SOCKSManager) handleConnect(ctx context.Context, clientConn net.Conn, targetAddr string) error {
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

	if err := writeSOCKSReply(clientConn, socksReplySucceeded, clientConn.LocalAddr().String()); err != nil {
		_ = remoteConn.Close()
		return err
	}

	closeBoth := sync.OnceFunc(func() {
		_ = clientConn.Close()
		_ = remoteConn.Close()
	})
	errCh := make(chan error, 2)
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
		host = addr
		port = "443"
	}
	return host, port, nil
}

func (m *SOCKSManager) negotiate(conn net.Conn) error {
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

	selected := byte(socksMethodNoAuth)
	if m.requiresUserPassAuth() {
		selected = byte(socksMethodUserPass)
	}
	if !containsByte(methods, selected) {
		_, _ = conn.Write([]byte{socksVersion5, socksMethodNoAcceptable})
		return fmt.Errorf("no acceptable socks method")
	}
	if _, err := conn.Write([]byte{socksVersion5, selected}); err != nil {
		return err
	}
	if selected == socksMethodUserPass {
		return m.handleUserPassAuth(conn)
	}
	return nil
}

func (m *SOCKSManager) requiresUserPassAuth() bool {
	return m.cfg.SOCKS.Username != "" || m.cfg.SOCKS.Password != ""
}

func (m *SOCKSManager) handleUserPassAuth(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksAuthVersion {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	passLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLen); err != nil {
		return err
	}
	password := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	if string(username) != m.cfg.SOCKS.Username || string(password) != m.cfg.SOCKS.Password {
		_, _ = conn.Write([]byte{socksAuthVersion, 0x01})
		return fmt.Errorf("socks authentication failed")
	}
	_, err := conn.Write([]byte{socksAuthVersion, 0x00})
	return err
}

func (m *SOCKSManager) handleUDPAssociate(ctx context.Context, conn net.Conn) error {
	m.mu.Lock()
	packetConn := m.udpPacketConn
	relay := m.udpRelay
	m.mu.Unlock()

	if packetConn == nil || relay == nil {
		_ = writeSOCKSReply(conn, socksReplyGeneralFailure, conn.LocalAddr().String())
		return fmt.Errorf("udp associate relay is not configured")
	}
	if err := writeSOCKSReply(conn, socksReplySucceeded, packetConn.LocalAddr().String()); err != nil {
		return err
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("split client host: %w", err)
	}
	assoc := &udpAssociation{
		clientHost: host,
		conn:       conn,
	}
	m.mu.Lock()
	if existing := m.associations[host]; existing != nil && existing.conn != conn {
		_ = existing.conn.Close()
	}
	m.associations[host] = assoc
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		if current := m.associations[host]; current == assoc {
			delete(m.associations, host)
		}
		m.mu.Unlock()
	}()

	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			if context.Cause(ctx) != nil || isClosedNetworkError(err) {
				return nil
			}
			return nil
		}
	}
}

func (m *SOCKSManager) udpLoop(ctx context.Context) {
	defer m.runWG.Done()

	buf := make([]byte, maxPacketBufferSize)
	for {
		m.mu.Lock()
		packetConn := m.udpPacketConn
		relay := m.udpRelay
		m.mu.Unlock()
		if packetConn == nil || relay == nil {
			return
		}

		n, clientAddr, err := packetConn.ReadFrom(buf)
		if err != nil {
			if context.Cause(ctx) != nil || isClosedNetworkError(err) {
				return
			}
			continue
		}

		clientHost, _, splitErr := net.SplitHostPort(clientAddr.String())
		if splitErr != nil {
			continue
		}

		m.mu.Lock()
		assoc := m.associations[clientHost]
		if assoc != nil {
			assoc.udpAddr = clientAddr
		}
		m.mu.Unlock()
		if assoc == nil {
			continue
		}

		target, payload, err := parseSOCKSUDPDatagram(buf[:n])
		if err != nil {
			continue
		}

		exchangeCtx, cancel := context.WithTimeout(ctx, m.cfg.ConnectTimeout)
		response, err := relay.Exchange(exchangeCtx, UDPAssociateRequest{
			TargetAddress: target,
			Payload:       payload,
		})
		cancel()
		if err != nil {
			continue
		}

		m.AddTxBytes(len(payload))
		if len(response.Payload) == 0 {
			continue
		}
		if response.SourceAddress == "" {
			response.SourceAddress = target
		}
		packet, err := buildSOCKSUDPDatagram(response.SourceAddress, response.Payload)
		if err != nil {
			continue
		}
		if _, err := packetConn.WriteTo(packet, clientAddr); err != nil {
			continue
		}
		m.AddRxBytes(len(response.Payload))
	}
}

func readSOCKSRequest(r io.Reader) (byte, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, "", err
	}
	if header[0] != socksVersion5 {
		return 0, "", fmt.Errorf("unsupported socks version: %d", header[0])
	}
	address, err := readSOCKSAddress(header[3], r)
	if err != nil {
		return 0, "", err
	}
	return header[1], address, nil
}

func writeSOCKSReply(w io.Writer, reply byte, address string) error {
	addrBytes, err := encodeSOCKSAddress(address)
	if err != nil {
		addrBytes, _ = encodeSOCKSAddress("0.0.0.0:0")
		reply = socksReplyAddressTypeNotSup
	}
	_, err = w.Write(append([]byte{socksVersion5, reply, 0x00}, addrBytes...))
	return err
}

func parseSOCKSUDPDatagram(packet []byte) (string, []byte, error) {
	if len(packet) < 4 {
		return "", nil, io.ErrUnexpectedEOF
	}
	if packet[2] != 0x00 {
		return "", nil, fmt.Errorf("udp fragmentation is not supported")
	}
	reader := bytesReader(packet[3:])
	target, err := readSOCKSAddress(reader.readByte(), &reader)
	if err != nil {
		return "", nil, err
	}
	return target, reader.remaining(), nil
}

func buildSOCKSUDPDatagram(address string, payload []byte) ([]byte, error) {
	addrBytes, err := encodeSOCKSAddress(address)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, 3+len(addrBytes)+len(payload))
	packet = append(packet, 0x00, 0x00, 0x00)
	packet = append(packet, addrBytes...)
	packet = append(packet, payload...)
	return packet, nil
}

func readSOCKSAddress(atyp byte, r io.Reader) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		host := make([]byte, 4)
		if _, err := io.ReadFull(r, host); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(host).String(), strconv.Itoa(port)), nil
	case socksAtypIPv6:
		host := make([]byte, 16)
		if _, err := io.ReadFull(r, host); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(host).String(), strconv.Itoa(port)), nil
	case socksAtypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(r, length); err != nil {
			return "", err
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, host); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(string(host), strconv.Itoa(port)), nil
	default:
		return "", fmt.Errorf("unsupported socks address type: %d", atyp)
	}
}

func encodeSOCKSAddress(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portValue, err := strconv.Atoi(portText)
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

func containsByte(values []byte, want byte) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func isClosedNetworkError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
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

func (r *bytesReader) remaining() []byte {
	return append([]byte(nil), (*r)...)
}
