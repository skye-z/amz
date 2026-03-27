package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
	"github.com/skye-z/amz/internal/config"
)

const (
	ProtocolCFConnectIP                   = internalcloudflare.ProtocolCFConnectIP
	CloudflareQuirkResponseError          = internalcloudflare.CloudflareQuirkResponseError
	CloudflareQuirkUnauthorized           = internalcloudflare.CloudflareQuirkUnauthorized
	CloudflareQuirkRateLimited            = internalcloudflare.CloudflareQuirkRateLimited
	CloudflareQuirkRouteUnavailable       = internalcloudflare.CloudflareQuirkRouteUnavailable
	CloudflareQuirkProtocolMismatch       = internalcloudflare.CloudflareQuirkProtocolMismatch
	CloudflareQuirkMissingDatagrams       = internalcloudflare.CloudflareQuirkMissingDatagrams
	CloudflareQuirkMissingExtendedConnect = internalcloudflare.CloudflareQuirkMissingExtendedConnect
	CloudflareQuirkProtocolError          = internalcloudflare.CloudflareQuirkProtocolError
)

type CloudflareQuirks = internalcloudflare.Quirks
type CloudflareSnapshot = internalcloudflare.Snapshot

// CloudflareCompatLayer 保留 kernel 旧入口，内部委托给 amz/cloudflare 的真实实现。
type CloudflareCompatLayer struct {
	snapshot CloudflareSnapshot
}

func DefaultCloudflareQuirks() CloudflareQuirks {
	return internalcloudflare.DefaultQuirks()
}

func NewCloudflareCompatLayer(cfg config.KernelConfig) (*CloudflareCompatLayer, error) {
	clone := cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return nil, fmt.Errorf("validate cloudflare config: %w", err)
	}
	return &CloudflareCompatLayer{snapshot: CloudflareSnapshot{
		Protocol: ProtocolCFConnectIP,
		Endpoint: clone.Endpoint,
		Quirks:   resolveCloudflareQuirks(clone.Endpoint),
	}}, nil
}

func resolveCloudflareQuirks(endpoint string) CloudflareQuirks {
	quirks := DefaultCloudflareQuirks()
	host, _, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		host = strings.TrimSpace(endpoint)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		quirks.UseCFConnectIP = false
		return quirks
	}
	if strings.EqualFold(host, "localhost") {
		quirks.UseCFConnectIP = false
	}
	return quirks
}

func (l *CloudflareCompatLayer) Snapshot() CloudflareSnapshot {
	if l == nil {
		return CloudflareSnapshot{}
	}
	return l.snapshot
}

func (l *CloudflareCompatLayer) ApplyConnectIPOptions(opts ConnectIPOptions) ConnectIPOptions {
	if l == nil {
		return opts
	}
	adjusted := opts
	if l.snapshot.Quirks.UseCFConnectIP {
		adjusted.Protocol = l.snapshot.Protocol
	}
	if l.snapshot.Quirks.RequireDatagrams {
		adjusted.EnableDatagrams = true
	}
	return adjusted
}

func (l *CloudflareCompatLayer) ApplyConnectStreamOptions(opts ConnectStreamOptions) ConnectStreamOptions {
	if l == nil {
		return opts
	}
	adjusted := opts
	adjusted.Protocol = internalcloudflare.ProtocolConnectStream
	return adjusted
}

func (l *CloudflareCompatLayer) WrapResponseError(operation string, statusCode int, cause error) error {
	if l == nil {
		return cause
	}
	if isCloudflareContextError(cause) {
		return cause
	}
	if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) && l.snapshot.Quirks.MapUnauthorizedToAuthError {
		cause = internalcloudflare.ErrAuthenticationFailed
	}
	return internalcloudflare.WrapError(operation, classifyCloudflareStatus(statusCode), cause)
}

func (l *CloudflareCompatLayer) WrapConnectIPError(operation string, rsp *http.Response, cause error) error {
	if l == nil || isCloudflareContextError(cause) {
		return cause
	}
	if rsp != nil {
		return l.WrapResponseError(operation, rsp.StatusCode, cause)
	}
	return l.WrapProtocolError(operation, cause)
}

func (l *CloudflareCompatLayer) WrapConnectStreamError(operation string, rsp *http.Response, cause error) error {
	if l == nil || isCloudflareContextError(cause) {
		return cause
	}
	if rsp != nil {
		return l.WrapResponseError(operation, rsp.StatusCode, cause)
	}
	return l.WrapProtocolError(operation, cause)
}

func (l *CloudflareCompatLayer) WrapProtocolError(operation string, cause error) error {
	if l == nil || isCloudflareContextError(cause) {
		return cause
	}
	return internalcloudflare.WrapError(operation, classifyCloudflareProtocolError(cause), cause)
}

func classifyCloudflareStatus(statusCode int) string {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return CloudflareQuirkUnauthorized
	case http.StatusTooManyRequests:
		return CloudflareQuirkRateLimited
	case http.StatusNotFound:
		return CloudflareQuirkRouteUnavailable
	case http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return CloudflareQuirkProtocolMismatch
	default:
		return CloudflareQuirkResponseError
	}
}

func classifyCloudflareProtocolError(cause error) string {
	if cause == nil {
		return CloudflareQuirkProtocolError
	}
	message := strings.ToLower(cause.Error())
	switch {
	case strings.Contains(message, "datagrams not enabled"), strings.Contains(message, "didn't enable datagrams"):
		return CloudflareQuirkMissingDatagrams
	case strings.Contains(message, "extended connect not enabled"), strings.Contains(message, "didn't enable extended connect"):
		return CloudflareQuirkMissingExtendedConnect
	case strings.Contains(message, "unexpected protocol"), strings.Contains(message, "capsule"), strings.Contains(message, "not implemented"):
		return CloudflareQuirkProtocolMismatch
	default:
		return CloudflareQuirkProtocolError
	}
}

func isCloudflareContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
