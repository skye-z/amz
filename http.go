package amz

import (
	"fmt"

	"github.com/skye-z/amz/config"
	httpproxy "github.com/skye-z/amz/proxy/http"
)

func NewHTTPProxy(cfg *config.KernelConfig) (HTTPProxy, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kernel config is required")
	}
	return httpproxy.NewManager(*cfg)
}
