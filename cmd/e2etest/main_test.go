package main

import (
	"bytes"
	"testing"
)

func TestBuildClientOptionsInjectsLoggerAndEndpoint(t *testing.T) {
	var buf bytes.Buffer
	logger := newAMZLogger(&buf)

	opts := buildClientOptions("127.0.0.1:19811", "./state.json", "162.159.198.1:443", logger)

	if opts.Logger == nil {
		t.Fatal("expected logger to be injected into amz options")
	}
	if opts.Transport.Endpoint != "162.159.198.1:443" {
		t.Fatalf("expected endpoint override to be kept, got %q", opts.Transport.Endpoint)
	}
	if !opts.HTTP.Enabled || !opts.SOCKS5.Enabled {
		t.Fatalf("expected http and socks5 to be enabled, got %+v", opts)
	}
}
