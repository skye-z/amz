package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/skye-z/amz/types"
)

const (
	// 默认端点指向 Cloudflare MASQUE 服务。
	DefaultEndpoint = "162.159.198.1:443"
	// 默认 SNI 与官方客户端观测值保持一致。
	DefaultSNI = "consumer-masque.cloudflareclient.com"
	// 默认 MTU 兼顾通用平台与隧道开销。
	DefaultMTU = 1280
)

const (
	// 默认保活间隔避免空闲连接过早回收。
	DefaultKeepalive = 30 * time.Second
	// 默认握手超时用于限制启动阻塞时间。
	DefaultConnectTimeout = 10 * time.Second
)

const (
	// ModeTUN 表示通过系统 TUN 暴露隧道。
	ModeTUN = "tun"
	// ModeSOCKS 表示通过 SOCKS5 暴露隧道。
	ModeSOCKS = "socks"
	// ModeHTTP 表示通过 HTTP 代理暴露隧道。
	ModeHTTP = "http"
)

// KernelConfig 描述内核启动所需的最小参数集合。
type KernelConfig struct {
	Endpoint       string
	SNI            string
	MTU            int
	Mode           string
	Keepalive      time.Duration
	ConnectTimeout time.Duration
}

// FillDefaults 为基础阶段补齐最小可运行默认值。
func (c *KernelConfig) FillDefaults() {
	if c.Endpoint == "" {
		c.Endpoint = DefaultEndpoint
	}
	if c.SNI == "" {
		c.SNI = DefaultSNI
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.Mode == "" {
		c.Mode = ModeTUN
	}
	if c.Keepalive == 0 {
		c.Keepalive = DefaultKeepalive
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}
}

// Validate 检查配置是否满足最小骨架约束。
func (c KernelConfig) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return fmt.Errorf("%w: endpoint is required", types.ErrInvalidConfig)
	}
	if strings.TrimSpace(c.SNI) == "" {
		return fmt.Errorf("%w: sni is required", types.ErrInvalidConfig)
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return fmt.Errorf("%w: mtu out of range", types.ErrInvalidConfig)
	}
	if c.Keepalive < 0 {
		return fmt.Errorf("%w: keepalive must be positive", types.ErrInvalidConfig)
	}
	if c.ConnectTimeout <= 0 {
		return fmt.Errorf("%w: connect timeout must be positive", types.ErrInvalidConfig)
	}
	switch c.Mode {
	case ModeTUN, ModeSOCKS, ModeHTTP:
		return nil
	default:
		return fmt.Errorf("%w: %q", types.ErrUnsupportedMode, c.Mode)
	}
}
