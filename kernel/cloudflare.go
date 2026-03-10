package kernel

import "github.com/skye-z/amz/config"

const (
	// ProtocolCFConnectIP 表示 Cloudflare 使用的 cf-connect-ip 协议变体。
	ProtocolCFConnectIP = "cf-connect-ip"
)

// CloudflareQuirks 描述最小兼容层需要暴露的协议差异开关。
type CloudflareQuirks struct {
	Name                       string
	UseCFConnectIP             bool
	RequireDatagrams           bool
	MapUnauthorizedToAuthError bool
}

// CloudflareSnapshot 描述兼容层对外暴露的最小配置快照。
type CloudflareSnapshot struct {
	Protocol string
	Endpoint string
	Quirks   CloudflareQuirks
}

// CloudflareCompatLayer 承接第一阶段的 Cloudflare 兼容占位能力。
type CloudflareCompatLayer struct {
	snapshot CloudflareSnapshot
}

// DefaultCloudflareQuirks 返回第一阶段默认启用的最小兼容开关。
func DefaultCloudflareQuirks() CloudflareQuirks {
	return CloudflareQuirks{
		Name:                       "cloudflare-default",
		UseCFConnectIP:             true,
		RequireDatagrams:           true,
		MapUnauthorizedToAuthError: true,
	}
}

// NewCloudflareCompatLayer 创建复用基础配置校验的最小兼容层。
func NewCloudflareCompatLayer(cfg config.KernelConfig) (*CloudflareCompatLayer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &CloudflareCompatLayer{
		snapshot: CloudflareSnapshot{
			Protocol: ProtocolCFConnectIP,
			Endpoint: cfg.Endpoint,
			Quirks:   DefaultCloudflareQuirks(),
		},
	}, nil
}

// Snapshot 返回兼容层的只读快照。
func (l *CloudflareCompatLayer) Snapshot() CloudflareSnapshot {
	return l.snapshot
}
