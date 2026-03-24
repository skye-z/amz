package kernel

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
	// 表示 Cloudflare 使用的 cf-connect-ip 协议变体。
	ProtocolCFConnectIP = "cf-connect-ip"
	// 表示通用响应错误。
	CloudflareQuirkResponseError = "response_error"
	// 表示鉴权或授权被拒绝。
	CloudflareQuirkUnauthorized = "unauthorized"
	// 表示远端限流。
	CloudflareQuirkRateLimited = "rate_limited"
	// 表示远端未暴露 CONNECT-IP 路由。
	CloudflareQuirkRouteUnavailable = "route_unavailable"
	// 表示协议能力或协议别名不兼容。
	CloudflareQuirkProtocolMismatch = "protocol_mismatch"
	// 表示远端未启用 H3 datagrams。
	CloudflareQuirkMissingDatagrams = "missing_datagrams"
	// 表示远端未启用 Extended CONNECT。
	CloudflareQuirkMissingExtendedConnect = "missing_extended_connect"
	// 表示其余协议阶段错误。
	CloudflareQuirkProtocolError = "protocol_error"
)

// 描述最小兼容层需要暴露的协议差异开关。
type CloudflareQuirks struct {
	Name                       string
	UseCFConnectIP             bool
	RequireDatagrams           bool
	MapUnauthorizedToAuthError bool
}

// 描述兼容层对外暴露的最小配置快照。
type CloudflareSnapshot struct {
	Protocol string
	Endpoint string
	Quirks   CloudflareQuirks
}

// 承接第一阶段的 Cloudflare 兼容占位能力。
type CloudflareCompatLayer struct {
	snapshot CloudflareSnapshot
}

// 返回第一阶段默认启用的最小兼容开关。
func DefaultCloudflareQuirks() CloudflareQuirks {
	return CloudflareQuirks{
		Name:                       "cloudflare-default",
		UseCFConnectIP:             true,
		RequireDatagrams:           true,
		MapUnauthorizedToAuthError: true,
	}
}

// 创建复用基础配置校验的最小兼容层。
func NewCloudflareCompatLayer(cfg config.KernelConfig) (*CloudflareCompatLayer, error) {
	clone := cfg
	clone.FillDefaults()
	if err := clone.Validate(); err != nil {
		return nil, fmt.Errorf("validate cloudflare config: %w", err)
	}
	return &CloudflareCompatLayer{
		snapshot: CloudflareSnapshot{
			Protocol: ProtocolCFConnectIP,
			Endpoint: clone.Endpoint,
			Quirks:   DefaultCloudflareQuirks(),
		},
	}, nil
}

// 返回兼容层的只读快照。
func (l *CloudflareCompatLayer) Snapshot() CloudflareSnapshot {
	return l.snapshot
}

// 将通用 CONNECT-IP 参数调整为 Cloudflare 兼容模式。
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

// 将通用 CONNECT-STREAM 参数调整为 Cloudflare 兼容模式 (2026 L4 Proxy)。
func (l *CloudflareCompatLayer) ApplyConnectStreamOptions(opts ConnectStreamOptions) ConnectStreamOptions {
	if l == nil {
		return opts
	}
	adjusted := opts
	adjusted.Protocol = ProtocolConnectStream
	return adjusted
}

// 为 Cloudflare 兼容分支补充错误上下文，并处理常见未授权映射。
func (l *CloudflareCompatLayer) WrapResponseError(operation string, statusCode int, cause error) error {
	if l == nil {
		return cause
	}
	if isContextError(cause) {
		return cause
	}
	if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) && l.snapshot.Quirks.MapUnauthorizedToAuthError {
		cause = types.ErrAuthenticationFailed
	}
	quirk := classifyCloudflareStatus(statusCode)
	return types.WrapCloudflareError(operation, quirk, cause)
}

// 基于真实 HTTP 响应或协议错误包装 Cloudflare 特殊响应。
func (l *CloudflareCompatLayer) WrapConnectIPError(operation string, rsp *http.Response, cause error) error {
	if l == nil || isContextError(cause) {
		return cause
	}
	if rsp != nil {
		return l.WrapResponseError(operation, rsp.StatusCode, cause)
	}
	return l.WrapProtocolError(operation, cause)
}

// 基于真实 HTTP 响应或协议错误包装 Cloudflare CONNECT-STREAM 特殊响应 (2026 L4 Proxy)。
func (l *CloudflareCompatLayer) WrapConnectStreamError(operation string, rsp *http.Response, cause error) error {
	if l == nil || isContextError(cause) {
		return cause
	}
	if rsp != nil {
		return l.WrapResponseError(operation, rsp.StatusCode, cause)
	}
	return l.WrapProtocolError(operation, cause)
}

// 基于真实协议阶段错误映射 Cloudflare 兼容分支。
func (l *CloudflareCompatLayer) WrapProtocolError(operation string, cause error) error {
	if l == nil || isContextError(cause) {
		return cause
	}
	return types.WrapCloudflareError(operation, classifyCloudflareProtocolError(cause), cause)
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

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
