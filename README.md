# amz

`amz` 是本仓库中的 WARP/MASQUE 内核层，负责：

- QUIC / HTTP/3 / CONNECT-IP 会话建立
- TUN、SOCKS5、HTTP 代理三种运行模式
- Cloudflare 兼容处理
- 数据面转发、路由与基础观测

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
sessMgr, err := kernel.NewConnectIPSessionManager(cfg)
if err != nil {
    panic(err)
}

if err := proxy.SetCoreTunnelDialer(connMgr, sessMgr, &net.Dialer{Timeout: cfg.ConnectTimeout}); err != nil {
    panic(err)
}
if err := proxy.Start(context.Background()); err != nil {
    panic(err)
}
defer proxy.Close()
```

## 关键模块

- `config/`
  - 内核配置模型与默认值
- `kernel/`
  - QUIC、CONNECT-IP、代理运行时、统计、Cloudflare 兼容
- `internal/tun/`
  - `sing-tun` 设备创建、地址配置、系统路由与回滚
- `types/`
  - 通用错误、状态、结构化统计输出

## 测试

```bash
go test ./amz/...
```

重点覆盖：

- QUIC / CONNECT-IP 建链
- TUN 设备与路由装配
- SOCKS5 / HTTP 代理运行时
- Cloudflare 兼容逻辑
- 结构化统计与日志脱敏

## 注意事项

- TUN 与系统路由修改通常需要管理员/root 权限。
- HTTP 代理虽已具备真实 CONNECT/转发运行时，但跨平台实际可用性仍依赖本机权限、路由环境与 WARP 端点可达性。
- 代理模式下请优先为测试环境使用随机监听地址（如 `127.0.0.1:0`），避免端口冲突。
