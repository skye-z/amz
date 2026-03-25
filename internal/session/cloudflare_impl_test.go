package session

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	internalcloudflare "github.com/skye-z/amz/internal/cloudflare"
	"github.com/skye-z/amz/internal/config"
)

func TestCloudflareCompatLayerDefaultsWithoutPublicImpl(t *testing.T) {
	layer, err := NewCloudflareCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	snapshot := layer.Snapshot()
	if snapshot.Protocol != internalcloudflare.ProtocolCFConnectIP {
		t.Fatalf("expected protocol %q, got %q", internalcloudflare.ProtocolCFConnectIP, snapshot.Protocol)
	}
	if snapshot.Endpoint != config.DefaultEndpoint {
		t.Fatalf("expected endpoint %q, got %q", config.DefaultEndpoint, snapshot.Endpoint)
	}
	if !snapshot.Quirks.RequireDatagrams {
		t.Fatal("expected datagram quirk enabled")
	}
}

func TestCloudflareCompatLayerWrapsProtocolErrorWithoutPublicImpl(t *testing.T) {
	layer, err := NewCloudflareCompatLayer(config.KernelConfig{})
	if err != nil {
		t.Fatalf("expected compat layer creation success, got %v", err)
	}

	err = layer.WrapProtocolError("connect-ip", errors.New("http3 settings: datagrams not enabled"))
	if !errors.Is(err, internalcloudflare.ErrCompat) {
		t.Fatalf("expected cloudflare compat error, got %v", err)
	}
	var compatErr *internalcloudflare.CompatError
	if !errors.As(err, &compatErr) {
		t.Fatal("expected contextual cloudflare compat error")
	}
	if compatErr.Quirk != internalcloudflare.CloudflareQuirkMissingDatagrams {
		t.Fatalf("expected quirk %q, got %q", internalcloudflare.CloudflareQuirkMissingDatagrams, compatErr.Quirk)
	}
	wrapped := layer.WrapConnectIPError("connect-ip", &http.Response{StatusCode: http.StatusTooManyRequests}, errors.New("rate limited"))
	if !errors.As(wrapped, &compatErr) {
		t.Fatal("expected contextual connect-ip compat error")
	}
	if compatErr.Quirk != internalcloudflare.CloudflareQuirkRateLimited {
		t.Fatalf("expected quirk %q, got %q", internalcloudflare.CloudflareQuirkRateLimited, compatErr.Quirk)
	}
}

func TestCloudflareCompatLayerDoesNotExposePublicImplType(t *testing.T) {
	layerType := reflect.TypeOf(CloudflareCompatLayer{})
	if _, ok := layerType.FieldByName("impl"); ok {
		t.Fatal("expected session compat layer to drop public impl field")
	}
	for i := 0; i < layerType.NumField(); i++ {
		if strings.Contains(layerType.Field(i).Type.String(), "cloudflare.CompatLayer") {
			t.Fatalf("expected session compat layer to avoid public cloudflare impl type, got %s", layerType.Field(i).Type.String())
		}
	}
}
