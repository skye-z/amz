# amz

> 面向 Cloudflare WARP 2026 Proxy Mode 的 SDK-first Go 实现。

`amz` 现在将根包视为主要对外入口。  
用户不需要理解底层 `session / proxy / tun / ...` 细节，推荐直接从：

```go
client, err := amz.NewClient(opts)
```

开始接入。

## 当前状态

截至 2026-03-25，当前 SDK 主线能力包括：

- ✅ 自动注册 / 复用设备身份
- ✅ 自动选点
- ✅ 本地状态存储（设备 ID、token、证书、账号状态、最后一次节点、节点缓存）
- ✅ HTTP Proxy Mode 主线已通过真实 `ipwho.is` 联调验证
- ✅ HTTP + SOCKS5 真单端口复用
- ✅ TUN 作为并行可选 runtime 接入

## 推荐用法

```go
package main

import (
	"context"

	"github.com/skye-z/amz"
)

func main() {
	client, err := amz.NewClient(amz.Options{
		Storage: amz.StorageOptions{
			Path: "./amz.state.json",
		},
		Listen: amz.ListenOptions{
			Address: "127.0.0.1:9811",
		},
		HTTP: amz.HTTPOptions{
			Enabled: true,
		},
		SOCKS5: amz.SOCKS5Options{
			Enabled: true,
		},
		TUN: amz.TUNOptions{
			Enabled: false,
		},
	})
	if err != nil {
		panic(err)
	}

	if err := client.Start(context.Background()); err != nil {
		panic(err)
	}
	defer client.Close()
}
```

## 设计要点

### 1. 根包是唯一主入口

SDK v1 默认只推荐通过根包接入：

- `NewClient`
- `Start`
- `Run`
- `Close`
- `Status`
- `ListenAddress`

### 2. HTTP 和 SOCKS5 真单端口复用

如果同时启用：

- `HTTP.Enabled = true`
- `SOCKS5.Enabled = true`

并设置：

```go
Listen: amz.ListenOptions{
    Address: "127.0.0.1:9811",
}
```

那么 SDK 只监听一个 TCP 端口，并按首包自动识别：

- SOCKS5 握手
- HTTP 代理请求

### 3. 存储只保存状态，不保存接入配置

`Storage.Path` 对应的状态文件仅保存：

- 设备 ID
- token
- 证书
- 账号状态
- 最后一次选中的节点
- 节点缓存

不会替接入应用持久化：

- 监听端口
- HTTP / SOCKS5 / TUN 开关

### 4. TUN 是并行可选能力

TUN 不参与单端口复用，而是作为与代理并行的 runtime。

## 真实链路验证

当前仓库已确认：

- 可以接入 WARP
- 代理流量确实经过主线转发
- `ipwho.is` 观测到出口 IP 变化

这意味着当前 SDK 所依赖的核心传输主线不是“只在单元测试里成立”，而是经过真实联调验证。

## API 概览

```go
type Options struct {
    Storage StorageOptions
    Listen  ListenOptions
    HTTP    HTTPOptions
    SOCKS5  SOCKS5Options
    TUN     TUNOptions
}
```

```go
client, err := amz.NewClient(opts)
err = client.Start(ctx)
defer client.Close()
```

阻塞式便捷入口：

```go
client, err := amz.NewClient(opts)
if err != nil {
    panic(err)
}
panic(client.Run())
```

## 适用场景

- 想快速接入一个可用的本地 WARP 代理 SDK
- 想同时提供 HTTP 和 SOCKS5 入口，但只暴露一个端口
- 想自动完成设备注册 / 复用与选点
- 想把现有 WARP 连接能力嵌入自己的程序

## 暂不包含

SDK v1 暂不聚焦：

- Team WARP
- Preferred / PreferredStrategy
- 丰富的公开事件流 API
- 应用侧配置持久化

## 文档语言

- [README.md](./README.md)
- [README_zh.md](./README_zh.md)

