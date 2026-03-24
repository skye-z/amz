# amz

> A SDK-first Go implementation for the Cloudflare WARP 2026 Proxy Mode path.

`amz` now treats the root package as the primary entry point.  
SDK users are expected to start with:

```go
client, err := amz.NewClient(opts)
```

instead of assembling lower-level transport components directly.

## Current Status

As of 2026-03-25, SDK v1 already includes:

- ✅ automatic registration / identity reuse
- ✅ automatic endpoint discovery
- ✅ local state persistence
- ✅ real HTTP Proxy Mode validation against `ipwho.is`
- ✅ true single-port multiplexing for HTTP + SOCKS5
- ✅ optional parallel TUN runtime

## Recommended Usage

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

## SDK Design

### Root package is the public surface

SDK v1 is centered on a small public API:

- `NewClient`
- `Start`
- `Run`
- `Close`
- `Status`
- `ListenAddress`

### HTTP and SOCKS5 share one real listener

If both are enabled and `Listen.Address` is set, the SDK opens **one** TCP listener and dispatches each accepted connection by sniffing the first bytes:

- SOCKS5 handshake
- HTTP proxy request

### Storage only keeps state

The SDK state file only stores:

- device ID
- token
- certificates
- account state
- last selected node
- node cache

It does **not** persist application-owned integration settings such as:

- whether HTTP / SOCKS5 / TUN is enabled
- listen port choices made by the embedding application

### TUN runs in parallel

TUN is not part of the single-port multiplexing path. It is managed as an optional parallel runtime under the same `Client`.

## Real Validation

The transport path behind the SDK has already been validated with real traffic:

- WARP connection established successfully
- traffic actually flowed through the mainline path
- `ipwho.is` observed a changed egress IP

That means the SDK is not built on top of a purely synthetic or mock-only path.

## API Shape

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

Blocking convenience entry:

```go
client, err := amz.NewClient(opts)
if err != nil {
    panic(err)
}
panic(client.Run())
```

## Good Fit For

- embedding a WARP-capable local proxy SDK
- exposing HTTP and SOCKS5 on a single port
- automatically registering / reusing device identity
- automatically selecting a usable WARP endpoint

## Not the Focus of SDK v1

- Team WARP
- Preferred / PreferredStrategy
- rich public event streaming
- persistence of application-level integration settings

## Other Languages

- [README_zh.md](./README_zh.md)

