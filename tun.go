package amz

import (
	"fmt"

	"github.com/skye-z/amz/config"
	tunruntime "github.com/skye-z/amz/tun"
)

func NewTunnel(cfg *config.KernelConfig) (Tunnel, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kernel config is required")
	}
	return tunruntime.NewRuntime(cfg)
}
