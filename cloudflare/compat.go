package cloudflare

import (
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

const (
	ProtocolCFConnectIP                   = kernel.ProtocolCFConnectIP
	CloudflareQuirkResponseError          = kernel.CloudflareQuirkResponseError
	CloudflareQuirkUnauthorized           = kernel.CloudflareQuirkUnauthorized
	CloudflareQuirkRateLimited            = kernel.CloudflareQuirkRateLimited
	CloudflareQuirkRouteUnavailable       = kernel.CloudflareQuirkRouteUnavailable
	CloudflareQuirkProtocolMismatch       = kernel.CloudflareQuirkProtocolMismatch
	CloudflareQuirkMissingDatagrams       = kernel.CloudflareQuirkMissingDatagrams
	CloudflareQuirkMissingExtendedConnect = kernel.CloudflareQuirkMissingExtendedConnect
	CloudflareQuirkProtocolError          = kernel.CloudflareQuirkProtocolError
)

type Quirks = kernel.CloudflareQuirks
type Snapshot = kernel.CloudflareSnapshot
type CompatLayer = kernel.CloudflareCompatLayer

func DefaultQuirks() Quirks {
	return kernel.DefaultCloudflareQuirks()
}

func NewCompatLayer(cfg config.KernelConfig) (*CompatLayer, error) {
	return kernel.NewCloudflareCompatLayer(cfg)
}
