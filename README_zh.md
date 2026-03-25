# AMZ - 第三方 Cloudflare WARP SDK

[English](./README.md) [中文](./README_zh.md) [![CI/CD](https://github.com/skye-z/amz/actions/workflows/ci.yml/badge.svg)](https://github.com/skye-z/amz/actions/workflows/ci.yml)

这是一个 Go SDK, 你可以用它来在你的应用里嵌入 Cloudflare WARP 代理

你只需要通过 `amz.NewClient(...)` 接入, 剩下的注册、状态复用、选点和 runtime 启动都由 SDK 统一编排管理

## 特性

- X25519MLKEM768 后量子加密
- HTTP、SOCKS5 和 TUN 代理
- L4 传输层代理
- 代理端口复用
- 自动注册
- 自动选点

## 适用场景

只想接入 Cloudflare WARP 来改变应用的外部IP, 用不到其他额外的功能, 不想使用官方 ~100MB 的客户端

我将其用于我的探针, 它被部署在1C1G 10GSSD的超小VPS上

## 为什么选择 AMZ

社区中有不少基于 WireGuard 实现的 WARP 库, 为什么我要选择用 AMZ 呢?

- 高性能: 在 Cloudflare 内部测试中, 使用 Quic L4 代理比 WireGuard 下载和上传速度翻倍, 延迟显著降低
- 小体积: 在完整实现了 WARP 最新代理模型的情况下做到了 ~1.1M 的编译大小
- 多通道: 内建了 HTTP、SOCKS5 和 TUN 代理通道, 并且具备良好的扩展性能快速扩展更多代理方式
- 更安全: 采用了更加现代的 X25519 搭配 ML‑KEM‑768 混合密钥实现抗量子攻击

## 路线图

- [ ] Team WARP
- [ ] 更复杂的优化策略

## 快速开始

```bash
go get github.com/skye-z/amz
```

下面是一个同时启用 HTTP 和 SOCKS5 代理通道的例子

```go
package main

import (
	"context"
	"log"

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
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	if err := client.Start(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("proxy listening on %s", client.ListenAddress())
}
```

如果你想用阻塞式, 可以直接调用 `Run()`：

```go
client, err := amz.NewClient(opts)
if err != nil {
	panic(err)
}
defer client.Close()

if err := client.Run(); err != nil {
	panic(err)
}
```
