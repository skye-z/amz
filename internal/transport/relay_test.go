package transport_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/skye-z/amz/internal/transport"
)

const errExpectedContextCanceled = "expected context canceled, got %v"

func TestNewPacketIO(t *testing.T) {
	io := transport.NewPacketIO(1600)
	if io.MTU() != 1600 {
		t.Fatalf("expected mtu 1600, got %d", io.MTU())
	}
	stats := io.Stats()
	if stats.RxPackets != 0 || stats.TxPackets != 0 {
		t.Fatalf("expected zero stats, got %+v", stats)
	}
}

func TestPacketIOForwardUplinkFragmentsAndForwardsICMP(t *testing.T) {
	io := transport.NewPacketIO(4)
	dev := newStubPacketDevice("igara0", 1280)
	endpoint := newStubPacketEndpoint()
	dev.EnqueueRead([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	endpoint.QueueICMP([]byte{9, 9, 9})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- io.ForwardUplink(ctx, dev, endpoint) }()

	waitForCondition(t, time.Second, func() bool { return len(endpoint.Writes()) == 3 && len(dev.Writes()) == 1 })
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(errExpectedContextCanceled, err)
	}
	writes := endpoint.Writes()
	if len(writes) != 3 {
		t.Fatalf("expected 3 fragments, got %d", len(writes))
	}
	expectPacket(t, writes[0], []byte{1, 2, 3, 4})
	expectPacket(t, writes[1], []byte{5, 6, 7, 8})
	expectPacket(t, writes[2], []byte{9})
	devWrites := dev.Writes()
	if len(devWrites) != 1 {
		t.Fatalf("expected 1 icmp packet, got %d", len(devWrites))
	}
	expectPacket(t, devWrites[0], []byte{9, 9, 9})
	stats := io.Stats()
	if stats.TxPackets != 3 || stats.TxBytes != 9 {
		t.Fatalf("unexpected tx stats: %+v", stats)
	}
	if stats.RxPackets != 1 || stats.RxBytes != 3 {
		t.Fatalf("unexpected rx stats: %+v", stats)
	}
}

func TestPacketIOForwardDownlinkWritesBackToDevice(t *testing.T) {
	io := transport.NewPacketIO(16)
	dev := newStubPacketDevice("igara0", 1280)
	endpoint := newStubPacketEndpoint()
	endpoint.EnqueueRead([]byte{7, 8, 9})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- io.ForwardDownlink(ctx, endpoint, dev) }()

	waitForCondition(t, time.Second, func() bool { return len(dev.Writes()) == 1 })
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(errExpectedContextCanceled, err)
	}
	writes := dev.Writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 downlink packet, got %d", len(writes))
	}
	expectPacket(t, writes[0], []byte{7, 8, 9})
	stats := io.Stats()
	if stats.RxPackets != 1 || stats.RxBytes != 3 {
		t.Fatalf("unexpected rx stats: %+v", stats)
	}
}

func TestPacketIORelayClosesEndpointOnCancel(t *testing.T) {
	io := transport.NewPacketIO(16)
	dev := newStubPacketDevice("igara0", 1280)
	endpoint := newStubPacketEndpoint()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- io.Relay(ctx, dev, endpoint) }()

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(errExpectedContextCanceled, err)
	}
	if !endpoint.Closed() {
		t.Fatal("expected endpoint to be closed on relay cancellation")
	}
}

type stubPacketDevice struct {
	name    string
	mtu     int
	readCh  chan []byte
	closeCh chan struct{}

	mu     sync.Mutex
	writes [][]byte
}

func newStubPacketDevice(name string, mtu int) *stubPacketDevice {
	return &stubPacketDevice{name: name, mtu: mtu, readCh: make(chan []byte, 8), closeCh: make(chan struct{})}
}

func (d *stubPacketDevice) Name() string { return d.name }
func (d *stubPacketDevice) MTU() int     { return d.mtu }

func (d *stubPacketDevice) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-d.closeCh:
		return 0, io.ErrClosedPipe
	case packet := <-d.readCh:
		return copy(dst, packet), nil
	}
}

func (d *stubPacketDevice) WritePacket(ctx context.Context, packet []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-d.closeCh:
		return 0, io.ErrClosedPipe
	default:
	}
	clone := append([]byte(nil), packet...)
	d.mu.Lock()
	d.writes = append(d.writes, clone)
	d.mu.Unlock()
	return len(packet), nil
}

func (d *stubPacketDevice) Close() error {
	select {
	case <-d.closeCh:
	default:
		close(d.closeCh)
	}
	return nil
}

func (d *stubPacketDevice) EnqueueRead(packet []byte) { d.readCh <- append([]byte(nil), packet...) }

func (d *stubPacketDevice) Writes() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, 0, len(d.writes))
	for _, packet := range d.writes {
		out = append(out, append([]byte(nil), packet...))
	}
	return out
}

type stubPacketEndpoint struct {
	readCh  chan []byte
	closeCh chan struct{}
	once    sync.Once

	mu     sync.Mutex
	writes [][]byte
	icmps  [][]byte
}

func newStubPacketEndpoint() *stubPacketEndpoint {
	return &stubPacketEndpoint{readCh: make(chan []byte, 8), closeCh: make(chan struct{})}
}

func (e *stubPacketEndpoint) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-e.closeCh:
		return 0, io.ErrClosedPipe
	case packet := <-e.readCh:
		return copy(dst, packet), nil
	}
}

func (e *stubPacketEndpoint) WritePacket(ctx context.Context, packet []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-e.closeCh:
		return nil, io.ErrClosedPipe
	default:
	}
	clone := append([]byte(nil), packet...)
	e.mu.Lock()
	e.writes = append(e.writes, clone)
	var icmp []byte
	if len(e.icmps) > 0 {
		icmp = append([]byte(nil), e.icmps[0]...)
		e.icmps = e.icmps[1:]
	}
	e.mu.Unlock()
	return icmp, nil
}

func (e *stubPacketEndpoint) Close() error {
	e.once.Do(func() { close(e.closeCh) })
	return nil
}

func (e *stubPacketEndpoint) Closed() bool {
	select {
	case <-e.closeCh:
		return true
	default:
		return false
	}
}

func (e *stubPacketEndpoint) EnqueueRead(packet []byte) { e.readCh <- append([]byte(nil), packet...) }
func (e *stubPacketEndpoint) QueueICMP(packet []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.icmps = append(e.icmps, append([]byte(nil), packet...))
}
func (e *stubPacketEndpoint) Writes() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([][]byte, 0, len(e.writes))
	for _, packet := range e.writes {
		out = append(out, append([]byte(nil), packet...))
	}
	return out
}

func expectPacket(t *testing.T, got, want []byte) {
	t.Helper()
	if string(got) != string(want) {
		t.Fatalf("expected packet %v, got %v", want, got)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
