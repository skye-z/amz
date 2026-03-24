package session

import (
	"net/http"

	"github.com/skye-z/amz/cloudflare"
	"github.com/skye-z/amz/config"
)

const (
	ProtocolCFConnectIP                   = cloudflare.ProtocolCFConnectIP
	CloudflareQuirkResponseError          = cloudflare.CloudflareQuirkResponseError
	CloudflareQuirkUnauthorized           = cloudflare.CloudflareQuirkUnauthorized
	CloudflareQuirkRateLimited            = cloudflare.CloudflareQuirkRateLimited
	CloudflareQuirkRouteUnavailable       = cloudflare.CloudflareQuirkRouteUnavailable
	CloudflareQuirkProtocolMismatch       = cloudflare.CloudflareQuirkProtocolMismatch
	CloudflareQuirkMissingDatagrams       = cloudflare.CloudflareQuirkMissingDatagrams
	CloudflareQuirkMissingExtendedConnect = cloudflare.CloudflareQuirkMissingExtendedConnect
	CloudflareQuirkProtocolError          = cloudflare.CloudflareQuirkProtocolError
)

type CloudflareQuirks = cloudflare.Quirks
type CloudflareSnapshot = cloudflare.Snapshot

// CloudflareCompatLayer 保留 kernel 旧入口，内部委托给 amz/cloudflare 的真实实现。
type CloudflareCompatLayer struct {
	impl *cloudflare.CompatLayer
}

func DefaultCloudflareQuirks() CloudflareQuirks {
	return cloudflare.DefaultQuirks()
}

func NewCloudflareCompatLayer(cfg config.KernelConfig) (*CloudflareCompatLayer, error) {
	impl, err := cloudflare.NewCompatLayer(cfg)
	if err != nil {
		return nil, err
	}
	return &CloudflareCompatLayer{impl: impl}, nil
}

func (l *CloudflareCompatLayer) Snapshot() CloudflareSnapshot {
	if l == nil || l.impl == nil {
		return CloudflareSnapshot{}
	}
	return l.impl.Snapshot()
}

func (l *CloudflareCompatLayer) ApplyConnectIPOptions(opts ConnectIPOptions) ConnectIPOptions {
	if l == nil || l.impl == nil {
		return opts
	}
	adjusted := l.impl.ApplyConnectIPOptions(cloudflare.ConnectIPOptions{
		Protocol:        opts.Protocol,
		EnableDatagrams: opts.EnableDatagrams,
	})
	opts.Protocol = adjusted.Protocol
	opts.EnableDatagrams = adjusted.EnableDatagrams
	return opts
}

func (l *CloudflareCompatLayer) ApplyConnectStreamOptions(opts ConnectStreamOptions) ConnectStreamOptions {
	if l == nil || l.impl == nil {
		return opts
	}
	adjusted := l.impl.ApplyConnectStreamOptions(cloudflare.ConnectStreamOptions{
		Protocol: opts.Protocol,
	})
	opts.Protocol = adjusted.Protocol
	return opts
}

func (l *CloudflareCompatLayer) WrapResponseError(operation string, statusCode int, cause error) error {
	if l == nil || l.impl == nil {
		return cause
	}
	return l.impl.WrapResponseError(operation, statusCode, cause)
}

func (l *CloudflareCompatLayer) WrapConnectIPError(operation string, rsp *http.Response, cause error) error {
	if l == nil || l.impl == nil {
		return cause
	}
	return l.impl.WrapConnectIPError(operation, rsp, cause)
}

func (l *CloudflareCompatLayer) WrapConnectStreamError(operation string, rsp *http.Response, cause error) error {
	if l == nil || l.impl == nil {
		return cause
	}
	return l.impl.WrapConnectStreamError(operation, rsp, cause)
}

func (l *CloudflareCompatLayer) WrapProtocolError(operation string, cause error) error {
	if l == nil || l.impl == nil {
		return cause
	}
	return l.impl.WrapProtocolError(operation, cause)
}
