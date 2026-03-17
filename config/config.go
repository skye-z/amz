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
	// DefaultSOCKSListenAddress 提供最小 SOCKS5 监听地址。
	DefaultSOCKSListenAddress = "127.0.0.1:1080"
	// DefaultHTTPListenAddress 提供最小 HTTP 代理监听地址。
	DefaultHTTPListenAddress = "127.0.0.1:8080"
)

// TUNConfig 描述 TUN 模式的最小参数。
type TUNConfig struct {
	Name string
}

// SOCKSConfig 描述 SOCKS 模式的最小参数。
type SOCKSConfig struct {
	ListenAddress string
	Username      string
	Password      string
	EnableUDP     bool
}

// HTTPConfig 描述 HTTP 模式的最小参数。
type HTTPConfig struct {
	ListenAddress string
}

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
	TUN            TUNConfig
	SOCKS          SOCKSConfig
	HTTP           HTTPConfig
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
	switch c.Mode {
	case ModeTUN:
		if c.TUN.Name == "" {
			c.TUN.Name = "igara0"
		}
	case ModeSOCKS:
		if c.SOCKS.ListenAddress == "" {
			c.SOCKS.ListenAddress = DefaultSOCKSListenAddress
		}
	case ModeHTTP:
		if c.HTTP.ListenAddress == "" {
			c.HTTP.ListenAddress = DefaultHTTPListenAddress
		}
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
	case ModeTUN:
		if strings.TrimSpace(c.TUN.Name) == "" {
			return fmt.Errorf("%w: tun name is required", types.ErrInvalidConfig)
		}
		return nil
	case ModeSOCKS:
		if strings.TrimSpace(c.SOCKS.ListenAddress) == "" {
			return fmt.Errorf("%w: socks listen address is required", types.ErrInvalidConfig)
		}
		return nil
	case ModeHTTP:
		if strings.TrimSpace(c.HTTP.ListenAddress) == "" {
			return fmt.Errorf("%w: http listen address is required", types.ErrInvalidConfig)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", types.ErrUnsupportedMode, c.Mode)
	}
}
