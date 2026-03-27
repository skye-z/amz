# AMZ - Third-Party Cloudflare WARP SDK

[English](./README_zh.md)

[![CI/CD](https://github.com/skye-z/amz/actions/workflows/ci.yml/badge.svg)](https://github.com/skye-z/amz/actions/workflows/ci.yml)

This is a Go SDK that allows you to embed the Cloudflare WARP proxy directly into your application.

You only need to integrate it via `amz.NewClient(...)`; the SDK will automatically handle registration, state persistence, endpoint selection, and runtime initialization.

## Features

- Post-quantum encryption with X25519MLKEM768
- HTTP, SOCKS5 proxies
- L4 transport layer proxy
- Proxy port reuse
- Automatic registration
- Automatic endpoint selection

## Use Cases

Ideal for applications that only need to change their external IP via Cloudflare WARP without additional features, and want to avoid the official ~100MB client.

I use this for my network probe, which is deployed on an ultra-small VPS with 1 CPU core, 1GB RAM, and 10GB SSD.

## Why Choose AMZ

There are several WARP libraries based on WireGuard in the community—why choose AMZ?

- High Performance: In internal Cloudflare tests, the QUIC L4 proxy achieves double the download and upload speeds compared to WireGuard, with significantly reduced latency.
- Small Size: ~1.1MB compiled binary with full implementation of the latest WARP proxy model
- Multi-Channel: Built-in HTTP, SOCKS5 proxy channels with excellent extensibility for adding more protocols
- Enhanced Security: Modern hybrid key exchange using X25519 + ML-KEM-768 for quantum-resistant encryption

## Roadmap

- [ ] TUN
- [ ] Team WARP
- [ ] Advanced optimization strategies

## Quick Start

```bash
go get github.com/skye-z/amz
```

Below is an example enabling both HTTP and SOCKS5 proxy channels:

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

For a blocking implementation, simply call `Run()`:

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
