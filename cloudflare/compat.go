package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

const (
	ProtocolCFConnectIP                   = "cf-connect-ip"
	ProtocolConnectStream                 = "connect-stream"
	CloudflareQuirkResponseError          = "response_error"
	CloudflareQuirkUnauthorized           = "unauthorized"
	CloudflareQuirkRateLimited            = "rate_limited"
	CloudflareQuirkRouteUnavailable       = "route_unavailable"
	CloudflareQuirkProtocolMismatch       = "protocol_mismatch"
	CloudflareQuirkMissingDatagrams       = "missing_datagrams"
	CloudflareQuirkMissingExtendedConnect = "missing_extended_connect"
	CloudflareQuirkProtocolError          = "protocol_error"
)

type Quirks struct {
	Name                       string
	UseCFConnectIP             bool
	RequireDatagrams           bool
	MapUnauthorizedToAuthError bool
}

type Snapshot struct {
	Protocol string
	Endpoint string
	Quirks   Quirks
}

type ConnectIPOptions struct {
	Protocol        string
	EnableDatagrams bool
}

type ConnectStreamOptions struct {
	Protocol string
}

type CompatLayer struct {
	snapshot Snapshot
}

func DefaultQuirks() Quirks {
	return Quirks{
		Name:                       "cloudflare-default",
		UseCFConnectIP:             true,
		RequireDatagrams:           true,
		MapUnauthorizedToAuthError: true,
	}
}

func NewCompatLayer(cfg config.KernelConfig) (*CompatLayer, error) {
	clone := cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return nil, fmt.Errorf("validate cloudflare config: %w", err)
	}
	return &CompatLayer{
		snapshot: Snapshot{
			Protocol: ProtocolCFConnectIP,
			Endpoint: clone.Endpoint,
			Quirks:   DefaultQuirks(),
		},
	}, nil
}

func (l *CompatLayer) Snapshot() Snapshot {
	if l == nil {
		return Snapshot{}
	}
	return l.snapshot
}

func (l *CompatLayer) ApplyConnectIPOptions(opts ConnectIPOptions) ConnectIPOptions {
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

func (l *CompatLayer) ApplyConnectStreamOptions(opts ConnectStreamOptions) ConnectStreamOptions {
	if l == nil {
		return opts
	}
	adjusted := opts
	adjusted.Protocol = ProtocolConnectStream
	return adjusted
}

func (l *CompatLayer) WrapResponseError(operation string, statusCode int, cause error) error {
	if l == nil {
		return cause
	}
	if isContextError(cause) {
		return cause
	}
	if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) && l.snapshot.Quirks.MapUnauthorizedToAuthError {
		cause = types.ErrAuthenticationFailed
	}
	quirk := classifyStatus(statusCode)
	return types.WrapCloudflareError(operation, quirk, cause)
}

func (l *CompatLayer) WrapConnectIPError(operation string, rsp *http.Response, cause error) error {
	if l == nil || isContextError(cause) {
		return cause
	}
	if rsp != nil {
		return l.WrapResponseError(operation, rsp.StatusCode, cause)
	}
	return l.WrapProtocolError(operation, cause)
}

func (l *CompatLayer) WrapConnectStreamError(operation string, rsp *http.Response, cause error) error {
	if l == nil || isContextError(cause) {
		return cause
	}
	if rsp != nil {
		return l.WrapResponseError(operation, rsp.StatusCode, cause)
	}
	return l.WrapProtocolError(operation, cause)
}

func (l *CompatLayer) WrapProtocolError(operation string, cause error) error {
	if l == nil || isContextError(cause) {
		return cause
	}
	return types.WrapCloudflareError(operation, classifyProtocolError(cause), cause)
}

func classifyStatus(statusCode int) string {
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

func classifyProtocolError(cause error) string {
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

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
