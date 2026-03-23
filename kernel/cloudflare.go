package kernel

import "github.com/skye-z/amz/config"

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

// 返回兼容层的只读快照。
func (l *CloudflareCompatLayer) Snapshot() CloudflareSnapshot {
	return l.snapshot
}
