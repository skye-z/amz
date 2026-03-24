package amz

import (
	"fmt"

	"github.com/skye-z/amz/config"
	socks5proxy "github.com/skye-z/amz/proxy/socks5"
)

func NewSOCKS5Proxy(cfg *config.KernelConfig) (SOCKS5Proxy, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kernel config is required")
	}
	return socks5proxy.NewManager(cfg)
}
