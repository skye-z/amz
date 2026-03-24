# amz

> A SDK-first WARP / MASQUE client core for the Cloudflare WARP 2026 Proxy Mode path.

`amz` now treats the root package as the primary user-facing entry point.  
Most implementation details live under `internal/`, while SDK users are expected
to start with:

```go
client, err := amz.NewClient(opts)
```

## Current Status

- ✅ HTTP Proxy Mode mainline validated against real `ipwho.is` traffic
- ✅ automatic registration / reuse, endpoint discovery, and local state storage
- ✅ HTTP + SOCKS5 true single-port multiplexing
- ✅ TUN can be enabled as a parallel runtime

## Quick Start

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

## SDK Model

`amz` v1 is designed around one `Client` instance that manages:

- local state storage
- automatic registration / reuse
- automatic endpoint discovery
- QUIC / HTTP3 / CONNECT stream transport
- one shared local listener for HTTP + SOCKS5
- optional TUN runtime

## Read in Your Preferred Language

- [简体中文 / Chinese](./README.zh-CN.md)
- [English](./README.en.md)
