# amz

`amz` 是本仓库中的 WARP/MASQUE 内核层，负责：

- QUIC / HTTP/3 / HTTP/3 CONNECT L4 代理会话建立 (2026 Proxy Mode)
- TUN、SOCKS5、HTTP 代理三种运行模式
- Cloudflare 兼容处理
- 数据面转发、路由与基础观测

> **注意**：自 2026 年 3 月 Cloudflare 官方博客宣布 Proxy Mode 重大更新后，WARP 已从 CONNECT-IP (L3) 方案彻底转向 **direct L4 proxying** (HTTP/3 CONNECT + QUIC streams)。本实现已对齐最新协议。

## 当前对外 API

### 配置

```go
cfg := config.KernelConfig{
    Endpoint: "162.159.198.1:443",
    SNI:      "consumer-masque.cloudflareclient.com",
    Mode:     config.ModeHTTP,
    HTTP: config.HTTPConfig{
        ListenAddress: "127.0.0.1:8080",
    },
}
cfg.FillDefaults()
if err := cfg.Validate(); err != nil {
    panic(err)
}
```

### TUN 生命周期

```go
tunKernel, err := kernel.NewTunnel(&cfg)
if err != nil {
    panic(err)
}
if err := tunKernel.Start(context.Background()); err != nil {
    panic(err)
}
defer tunKernel.Close()
```

### SOCKS5 模式

```go
cfg.Mode = config.ModeSOCKS
cfg.SOCKS.ListenAddress = "127.0.0.1:1080"
cfg.SOCKS.EnableUDP = true

socks, err := kernel.NewSOCKSManager(&cfg)
if err != nil {
    panic(err)
}
if err := socks.Start(context.Background()); err != nil {
    panic(err)
}
defer socks.Close()
```

### HTTP 代理模式

```go
cfg.Mode = config.ModeHTTP
cfg.HTTP.ListenAddress = "127.0.0.1:8080"

proxy, err := kernel.NewHTTPProxyManager(cfg)
if err != nil {
    panic(err)
}

connMgr, err := kernel.NewConnectionManager(cfg)
if err != nil {
    panic(err)
}

// 2026 L4 Proxy: 使用 ConnectStreamManager (HTTP/3 CONNECT stream)
streamMgr, err := kernel.NewConnectStreamManager(cfg)
if err != nil {
    panic(err)
}

// 绑定 HTTP/3 连接并设置 stream manager
connMgr.Connect(context.Background())
streamMgr.BindHTTP3Conn(connMgr.HTTP3Conn())
streamMgr.SetReady()

proxy.SetStreamManager(streamMgr)
if err := proxy.Start(context.Background()); err != nil {
    panic(err)
}
defer proxy.Close()
```

## 关键模块

- `config/`
  - 内核配置模型与默认值
- `kernel/`
  - QUIC、HTTP/3 CONNECT (L4)、SOCKS5/HTTP 代理运行时、统计、Cloudflare 兼容
  - **2026 更新**：`connect_stream.go` - L4 stream relay 实现 (HTTP/3 CONNECT)
  - **兼容路径**：`connectip.go` - 旧版 CONNECT-IP 实现 (保留用于 2025 客户端兼容)
- `internal/tun/`
  - `sing-tun` 设备创建、地址配置、系统路由与回滚
- `types/`
  - 通用错误、状态、结构化统计输出

## 测试

```bash
go test ./amz/...
```

重点覆盖：

- QUIC / HTTP/3 CONNECT (L4) 建链
- TUN 设备与路由装配
- SOCKS5 / HTTP 代理运行时
- Cloudflare 兼容逻辑
- 结构化统计与日志脱敏
- HTTP/3 CONNECT stream 生命周期

## 注意事项

- TUN 与系统路由修改通常需要管理员/root 权限。
- HTTP 代理虽已具备真实 CONNECT/转发运行时，但跨平台实际可用性仍依赖本机权限、路由环境与 WARP 端点可达性。
- 代理模式下请优先为测试环境使用随机监听地址（如 `127.0.0.1:0`），避免端口冲突。
