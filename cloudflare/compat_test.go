package cloudflare_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/skye-z/amz/cloudflare"
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/types"
)

func TestNewCompatLayerAppliesDefaults(t *testing.T) {
	layer, err := cloudflare.NewCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected compat layer creation with defaults, got %v", err)
	}

	snapshot := layer.Snapshot()
	if snapshot.Protocol != cloudflare.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", cloudflare.ProtocolCFConnectIP, snapshot.Protocol)
	}
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, snapshot.Endpoint)
	}
	if !snapshot.Quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
}

func TestCompatLayerApplyConnectIPOptions(t *testing.T) {
	layer, err := cloudflare.NewCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	adjusted := layer.ApplyConnectIPOptions(cloudflare.ConnectIPOptions{
		Protocol:        "connect-ip",
		EnableDatagrams: false,
	})
	if adjusted.Protocol != cloudflare.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", cloudflare.ProtocolCFConnectIP, adjusted.Protocol)
	}
	if !adjusted.EnableDatagrams {
		t.Fatal("expected datagrams forced by cloudflare quirks")
	}
}

func TestCompatLayerWrapProtocolError(t *testing.T) {
	layer, err := cloudflare.NewCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	wrapped := layer.WrapProtocolError("connect-ip", errors.New("http3 settings: datagrams not enabled"))
	if !errors.Is(wrapped, types.ErrCloudflareCompat) {
		t.Fatal("expected cloudflare compat error")
	}

	var compatErr *types.CloudflareCompatError
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected contextual cloudflare error")
	}
	if compatErr.Quirk != cloudflare.CloudflareQuirkMissingDatagrams {
		t.Fatalf("expected quirk %q, got %q", cloudflare.CloudflareQuirkMissingDatagrams, compatErr.Quirk)
	}
}

func TestCompatLayerWrapConnectIPErrorUsesResponse(t *testing.T) {
	layer, err := cloudflare.NewCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	wrapped := layer.WrapConnectIPError("connect-ip", &http.Response{StatusCode: http.StatusTooManyRequests}, errors.New("rate limited"))
	var compatErr *types.CloudflareCompatError
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected contextual cloudflare error")
	}
	if compatErr.Quirk != cloudflare.CloudflareQuirkRateLimited {
		t.Fatalf("expected quirk %q, got %q", cloudflare.CloudflareQuirkRateLimited, compatErr.Quirk)
	}
}
