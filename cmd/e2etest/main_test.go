package main

import (
	"bytes"
	"testing"

	"github.com/skye-z/amz/internal/testkit"
)

func TestBuildClientOptionsInjectsLoggerAndEndpoint(t *testing.T) {
	var buf bytes.Buffer
	logger := newAMZLogger(&buf)

	opts := buildClientOptions(testkit.LocalListenSDK, "./state.json", testkit.WarpIPv4Primary443, logger)

	if opts.Logger == nil {
		t.Fatal("expected logger to be injected into amz options")
	}
	if opts.Transport.Endpoint != testkit.WarpIPv4Primary443 {
		t.Fatalf("expected endpoint override to be kept, got %q", opts.Transport.Endpoint)
	}
	if !opts.HTTP.Enabled || !opts.SOCKS5.Enabled {
		t.Fatalf("expected http and socks5 to be enabled, got %+v", opts)
	}
}

func TestBuildClientOptionsCanEnableTUNOnly(t *testing.T) {
	var buf bytes.Buffer
	logger := newAMZLogger(&buf)

	opts := buildClientOptionsForModes(testkit.LocalListenSDK, "./state.json", "", logger, false, false, true)

	if !opts.TUN.Enabled {
		t.Fatal("expected tun to be enabled")
	}
	if opts.HTTP.Enabled || opts.SOCKS5.Enabled {
		t.Fatalf("expected http/socks5 to be disabled, got %+v", opts)
	}
}

func TestShouldRunModeFlags(t *testing.T) {
	tests := []struct {
		name      string
		skipHTTP  bool
		skipSOCKS bool
		skipTUN   bool
		http      bool
		socks     bool
		tun       bool
	}{
		{name: "run all", http: true, socks: true, tun: true},
		{name: "skip tun", skipTUN: true, http: true, socks: true, tun: false},
		{name: "skip http", skipHTTP: true, http: false, socks: true, tun: true},
		{name: "skip socks", skipSOCKS: true, http: true, socks: false, tun: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			http, socks, tun := shouldRunModes(tt.skipHTTP, tt.skipSOCKS, tt.skipTUN)
			if http != tt.http || socks != tt.socks || tun != tt.tun {
				t.Fatalf("expected (%v,%v,%v), got (%v,%v,%v)", tt.http, tt.socks, tt.tun, http, socks, tun)
			}
		})
	}
}

func TestDefaultIPTransportDisablesConnectionReuse(t *testing.T) {
	transport := defaultIPTransport()
	if transport == nil {
		t.Fatal("expected direct transport")
	}
	if !transport.DisableKeepAlives {
		t.Fatal("expected keepalives disabled to avoid reusing pre-tunnel direct connections")
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("expected http2 disabled for deterministic direct/tun checks")
	}
}
