# amz

> WARP / MASQUE transport kernel for the Cloudflare WARP 2026 Proxy Mode path.
>
> `amz` provides the protocol and runtime layer used by this repository: QUIC, HTTP/3, HTTP/3 CONNECT stream relay, proxy runtimes, tunnel scaffolding, and Cloudflare-specific compatibility behavior.

## Overview

`amz` is the transport kernel module in this repository.

It is designed for two audiences at the same time:

- **internal integration** — as the runtime engine behind `igara`
- **external embedding** — as a reusable Go package for proxy / tunnel integration

The current mainline is aligned with **Cloudflare WARP 2026 Proxy Mode**, which is centered on:

- **QUIC + HTTP/3**
- **HTTP/3 CONNECT**
- **direct L4 proxying over streams**

As of **March 24, 2026**, the HTTP proxy mainline has been validated against real [`ipwho.is`](https://ipwho.is/) traffic with a confirmed egress IP change.

## Read in Your Preferred Language

- [简体中文 / Chinese](./README.zh-CN.md)
- [English](./README.en.md)

## Current Status

- **Validated mainline:** HTTP Proxy Mode over QUIC / HTTP/3 / HTTP/3 CONNECT
- **Available runtime surfaces:** HTTP proxy, SOCKS5 proxy, TUN scaffolding
- **Compatibility path:** CONNECT-IP is still present for TUN / legacy-style completion work

## Public Package Surface

The root package now acts as the primary façade:

```go
proxy, err := amz.NewHTTPProxy(cfg)
socks, err := amz.NewSOCKS5Proxy(cfg)
tun, err := amz.NewTunnel(cfg)
```

Supporting packages are organized by responsibility:

- `config/` — configuration model, defaults, validation
- `session/` — QUIC / HTTP/3 / CONNECT stream / CONNECT-IP session primitives
- `proxy/http/` — HTTP proxy runtime
- `proxy/socks5/` — SOCKS5 runtime
- `tun/` — TUN-related surface
- `datapath/` — packet relay abstractions
- `cloudflare/` — Cloudflare compatibility surface
- `observe/` — stats / sanitization-facing types

## Quick Example

```go
package main

import (
    "context"

    "github.com/skye-z/amz"
    "github.com/skye-z/amz/config"
)

func main() {
    cfg := &config.KernelConfig{
        Endpoint: "162.159.198.2:443",
        SNI:      "warp.cloudflare.com",
        Mode:     config.ModeHTTP,
        HTTP: config.HTTPConfig{
            ListenAddress: "127.0.0.1:8080",
        },
    }
    cfg.FillDefaults()

    proxy, err := amz.NewHTTPProxy(cfg)
    if err != nil {
        panic(err)
    }
    defer proxy.Close()

    if err := proxy.Start(context.Background()); err != nil {
        panic(err)
    }
}
```

## Recommended Reading Order

If you're new to this module:

1. Start with [README.zh-CN.md](./README.zh-CN.md) or [README.en.md](./README.en.md)
2. Use the **HTTP Proxy Mode** examples first
3. Treat **TUN / CONNECT-IP** as a compatibility-oriented path still being completed
