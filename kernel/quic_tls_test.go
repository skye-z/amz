package kernel

import (
	"crypto/ecdsa"
	"crypto/tls"
	"testing"

	"github.com/skye-z/amz/config"
)

// 验证 TLS 配置会装配客户端证书材料。
func TestBuildTLSConfigIncludesClientCertificate(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{
		ServerName:        config.DefaultSNI,
		ClientPrivateKey:  testClientPrivateKeyBase64,
		ClientCertificate: testClientCertificateBase64,
	})
	if tlsCfg.ServerName != config.DefaultSNI {
		t.Fatalf("expected server name %q, got %q", config.DefaultSNI, tlsCfg.ServerName)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("expected one client certificate, got %d", len(tlsCfg.Certificates))
	}
	if _, ok := tlsCfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatal("expected parsed client private key in tls certificate")
	}
}

// 验证无效证书材料不会污染 TLS 配置。
func TestBuildTLSConfigSkipsInvalidClientCertificate(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{
		ServerName:        config.DefaultSNI,
		ClientPrivateKey:  "invalid",
		ClientCertificate: "invalid",
	})
	if len(tlsCfg.Certificates) != 0 {
		t.Fatalf("expected no client certificate on invalid materials, got %d", len(tlsCfg.Certificates))
	}
}

var _ tls.Certificate

const (
	testClientPrivateKeyBase64  = "MHcCAQEEIP2wC9ZwTe74MkRUYw35vj0IadB1iKsFcfoTmyaKOAqvoAoGCCqGSM49AwEHoUQDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzmw=="
	testClientCertificateBase64 = "MIIBCDCBr6ADAgECAgEAMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMTCWlnYXJhLXRlc3QwHhcNMjYwMzI0MDAwMDAwWhcNMjYwMzI1MDAwMDAwWjAUMRIwEAYDVQQDEwlpZ2FyYS10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzm6MSMBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0kAMEYCIQDYPe0nLBKBPXn1HULICwhf66A1VpzwuNFuIBqmoeZa9QIhAJ6xPD58Ll35H5TADaBrZEcD3xKhsR4HIX66vepQP9en"
)
