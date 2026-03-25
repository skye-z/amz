package session

import (
	"testing"
	"time"

	"github.com/skye-z/amz/internal/config"
)

// 验证 QUIC 连接参数会从内核配置中生成。
func TestBuildQUICOptions(t *testing.T) {
	options, err := BuildQUICOptions(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected quic options, got %v", err)
	}
	if options.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, options.Endpoint)
	}
	if options.ServerName != config.DefaultSNI {
		t.Fatalf("expected server name %q, got %q", config.DefaultSNI, options.ServerName)
	}
	if options.EnableDatagrams != true {
		t.Fatal("expected datagrams enabled")
	}
}

// 验证 QUIC 参数构造会补齐默认值并保持最小传输开关。
func TestBuildQUICOptionsAppliesDefaults(t *testing.T) {
	options, err := BuildQUICOptions(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected quic options with defaults, got %v", err)
	}
	if options.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, options.Endpoint)
	}
	if options.ServerName != config.DefaultSNI {
		t.Fatalf("expected server name %q, got %q", config.DefaultSNI, options.ServerName)
	}
	if options.Keepalive != config.DefaultKeepalive.String() {
		t.Fatalf("expected keepalive %q, got %q", config.DefaultKeepalive.String(), options.Keepalive)
	}
	if !options.EnableDatagrams {
		t.Fatal("expected datagrams enabled")
	}
}

// 验证 HTTP/3 连接参数会复用 QUIC 连接信息。
func TestBuildHTTP3Options(t *testing.T) {
	http3Options := BuildHTTP3Options(QUICOptions{
		Endpoint:        config.DefaultEndpoint,
		ServerName:      config.DefaultSNI,
		EnableDatagrams: true,
	})
	if http3Options.Authority != config.DefaultEndpoint {
		t.Fatalf("expected authority %q, got %q", config.DefaultEndpoint, http3Options.Authority)
	}
	if !http3Options.EnableDatagrams {
		t.Fatal("expected datagrams enabled")
	}
}

// 验证 QUIC 连接参数会预留拥塞控制与连接参数扩展点。
func TestBuildQUICOptionsWithExtensions(t *testing.T) {
	options, err := BuildQUICOptions(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
		QUIC: config.QUICConfig{
			CongestionControl: "bbr",
			ConnectionParameters: map[string]string{
				"max_streams": "16",
			},
		},
	})
	if err != nil {
		t.Fatalf("expected quic options, got %v", err)
	}
	if options.CongestionControl != "bbr" {
		t.Fatalf("expected congestion control %q, got %q", "bbr", options.CongestionControl)
	}
	if got := options.ConnectionParameters["max_streams"]; got != "16" {
		t.Fatalf("expected connection parameter %q, got %q", "16", got)
	}
}

// 验证 QUIC 参数会复制配置中的连接参数，避免后续变更污染传输层快照。
func TestBuildQUICOptionsCopiesConfigConnectionParameters(t *testing.T) {
	cfg := config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
		QUIC: config.QUICConfig{
			ConnectionParameters: map[string]string{
				"masque_version": "draft-08",
			},
		},
	}

	options, err := BuildQUICOptions(cfg)
	if err != nil {
		t.Fatalf("expected quic options, got %v", err)
	}

	cfg.QUIC.ConnectionParameters["masque_version"] = "mutated"
	if got := options.ConnectionParameters["masque_version"]; got != "draft-08" {
		t.Fatalf("expected copied connection parameter %q, got %q", "draft-08", got)
	}
}

// 验证 HTTP/3 连接参数会继承并隔离 QUIC 连接扩展参数。
func TestBuildHTTP3OptionsCopiesConnectionParameters(t *testing.T) {
	http3Options := BuildHTTP3Options(QUICOptions{
		Endpoint:        config.DefaultEndpoint,
		ServerName:      config.DefaultSNI,
		EnableDatagrams: true,
		ConnectionParameters: map[string]string{
			"masque_version": "draft-08",
		},
	})
	if got := http3Options.ConnectionParameters["masque_version"]; got != "draft-08" {
		t.Fatalf("expected connection parameter %q, got %q", "draft-08", got)
	}
	http3Options.ConnectionParameters["masque_version"] = "changed"
	quicOptions := QUICOptions{
		ConnectionParameters: map[string]string{
			"masque_version": "draft-08",
		},
	}
	isolated := BuildHTTP3Options(quicOptions)
	isolated.ConnectionParameters["masque_version"] = "changed"
	if quicOptions.ConnectionParameters["masque_version"] != "draft-08" {
		t.Fatal("expected http3 connection parameters to be copied")
	}
}

// 验证连接管理器会暴露最小状态快照。
func TestConnectionManagerSnapshot(t *testing.T) {
	manager, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}
	snapshot := manager.Snapshot()
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, snapshot.Endpoint)
	}
	if snapshot.State != ConnStateIdle {
		t.Fatalf("expected idle state, got %q", snapshot.State)
	}
}

// 验证连接管理器会暴露基础连接统计入口。
func TestConnectionManagerStats(t *testing.T) {
	manager, err := NewConnectionManager(config.KernelConfig{
		Endpoint:       config.DefaultEndpoint,
		SNI:            config.DefaultSNI,
		MTU:            config.DefaultMTU,
		Mode:           config.ModeSOCKS,
		ConnectTimeout: config.DefaultConnectTimeout,
		Keepalive:      config.DefaultKeepalive,
		SOCKS: config.SOCKSConfig{
			ListenAddress: config.DefaultSOCKSListenAddress,
		},
	})
	if err != nil {
		t.Fatalf("expected manager creation success, got %v", err)
	}

	manager.RecordHandshakeLatency(120 * time.Millisecond)
	manager.AddTxBytes(128)
	manager.AddRxBytes(256)

	stats := manager.Stats()
	if stats.HandshakeLatency != 120*time.Millisecond {
		t.Fatalf("expected handshake latency 120ms, got %s", stats.HandshakeLatency)
	}
	if stats.TxBytes != 128 {
		t.Fatalf("expected tx bytes 128, got %d", stats.TxBytes)
	}
	if stats.RxBytes != 256 {
		t.Fatalf("expected rx bytes 256, got %d", stats.RxBytes)
	}
}
