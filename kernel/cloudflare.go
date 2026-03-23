package kernel

import (
	"fmt"

	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

const (
	// 表示 Cloudflare 使用的 cf-connect-ip 协议变体。
	ProtocolCFConnectIP = "cf-connect-ip"
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

// 为 Cloudflare 兼容分支补充错误上下文，并处理常见未授权映射。
func (l *CloudflareCompatLayer) WrapResponseError(operation string, statusCode int, cause error) error {
	if statusCode == 401 && l.snapshot.Quirks.MapUnauthorizedToAuthError {
		cause = types.ErrAuthenticationFailed
	}
	quirk := "response_error"
	if statusCode == 401 {
		quirk = "unauthorized"
	}
	return types.WrapCloudflareError(operation, quirk, cause)
}
