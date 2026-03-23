package packet

import "sync"

// 描述可复用的数据包缓冲。
type Buffer struct {
	Data []byte
	N    int
}

// 描述最小收发统计快照。
type Snapshot struct {
	RxPackets int
	TxPackets int
	RxBytes   int
	TxBytes   int
}

// 管理固定大小缓冲区复用。
type BufferPool struct {
	size int
	pool sync.Pool
}

// 管理上下行包计数与字节统计。
type Stats struct {
	mu       sync.Mutex
	snapshot Snapshot
}

// 创建固定大小缓冲池。
func NewBufferPool(size int) *BufferPool {
	bp := &BufferPool{size: size}
	bp.pool.New = func() any {
		return &Buffer{Data: make([]byte, size)}
	}
	return bp
}

// 获取一个可复用缓冲。
func (p *BufferPool) Get() *Buffer {
	buf := p.pool.Get().(*Buffer)
	buf.N = 0
	return buf
}

// 归还一个缓冲以便复用。
func (p *BufferPool) Put(buf *Buffer) {
	if buf == nil {
		return
	}
	buf.N = 0
	p.pool.Put(buf)
}

// 创建最小统计管理器。
func NewStats() *Stats {
	return &Stats{}
}

// 记录一次下行收包。
func (s *Stats) AddRx(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.RxPackets++
	s.snapshot.RxBytes += n
}

// 记录一次上行发包。
func (s *Stats) AddTx(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot.TxPackets++
	s.snapshot.TxBytes += n
}

// 返回统计快照。
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot
}
