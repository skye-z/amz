package session

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"testing"

	"github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/testkit"
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
	if tlsCfg.InsecureSkipVerify {
		t.Fatal("expected tls config to keep certificate verification enabled")
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("expected tls config to carry a root CA pool")
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

func TestBuildTLSConfigUsesDefaultSNIWhenUnset(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{})
	if tlsCfg.ServerName != config.DefaultSNI {
		t.Fatalf("expected default server name %q, got %q", config.DefaultSNI, tlsCfg.ServerName)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Fatal("expected default tls config to verify peer certificates")
	}
}

func TestBuildTLSConfigUsesPinnedMASQUEVerificationForAltPorts(t *testing.T) {
	tlsCfg := buildTLSConfig(QUICOptions{
		Endpoint:          testkit.WarpIPv4Alt500,
		ServerName:        config.DefaultSNI,
		PeerPublicKey:     testMASQUEPeerPublicKeyPEM,
		ClientPrivateKey:  testClientPrivateKeyBase64,
		ClientCertificate: testClientCertificateBase64,
	})
	if tlsCfg.ServerName != "masque.cloudflareclient.com" {
		t.Fatalf("expected MASQUE server name, got %q", tlsCfg.ServerName)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Fatal("expected pinned MASQUE mode to enable custom verification path")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Fatal("expected pinned MASQUE verifier")
	}
}

func TestPinnedMASQUEVerifierAcceptsMatchingLeaf(t *testing.T) {
	verifier := buildPinnedMASQUEVerifier("masque.cloudflareclient.com", testMASQUEPeerPublicKeyPEM)
	raw, err := base64.StdEncoding.DecodeString(testMASQUELeafCertBase64)
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if err := verifier([][]byte{raw}, nil); err != nil {
		t.Fatalf("expected verifier success, got %v", err)
	}
}

func TestPinnedMASQUEVerifierRejectsWrongPinnedKey(t *testing.T) {
	verifier := buildPinnedMASQUEVerifier("masque.cloudflareclient.com", testOtherPublicKeyPEM)
	raw, err := base64.StdEncoding.DecodeString(testMASQUELeafCertBase64)
	if err != nil {
		t.Fatalf("decode cert: %v", err)
	}
	if err := verifier([][]byte{raw}, nil); err == nil {
		t.Fatal("expected verifier failure for mismatched pinned key")
	}
}

var _ tls.Certificate

const (
	testClientPrivateKeyBase64  = "MHcCAQEEIP2wC9ZwTe74MkRUYw35vj0IadB1iKsFcfoTmyaKOAqvoAoGCCqGSM49AwEHoUQDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzmw=="
	testClientCertificateBase64 = "MIIBCDCBr6ADAgECAgEAMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMTCWlnYXJhLXRlc3QwHhcNMjYwMzI0MDAwMDAwWhcNMjYwMzI1MDAwMDAwWjAUMRIwEAYDVQQDEwlpZ2FyYS10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzm6MSMBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0kAMEYCIQDYPe0nLBKBPXn1HULICwhf66A1VpzwuNFuIBqmoeZa9QIhAJ6xPD58Ll35H5TADaBrZEcD3xKhsR4HIX66vepQP9en"
	testMASQUELeafCertBase64    = "MIICPzCCAcWgAwIBAgIUc2dOs+UVA8fE6UO4F/QWdHT8JoEwCgYIKoZIzj0EAwMwTjELMAkGA1UEBhMCVVMxGTAXBgNVBAoMEENsb3VkZmxhcmUsIEluYy4xJDAiBgNVBAMMGzIwMjQtMDItMjcgU2VsZi1TaWduZWQgUm9vdDAeFw0yNjAxMjYxMDQ1MDZaFw0yNzAyMjYxMDQ1MDZaMCYxJDAiBgNVBAMMG21hc3F1ZS5jbG91ZGZsYXJlY2xpZW50LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCGlOzE6CZvTSqfGHxsUeq/v4eJnBu0sSPLbFvDkdQObb/8ws1WwkUYdrfO/5MZz+pQMtJZK+6mMLvqMfpN3a+ujgagwgaUwHQYDVR0OBBYEFMv1d+q9sqfM3gXICqoYHSa7GKJMMB8GA1UdIwQYMBaAFFDWHnoISkfPE/lnoezNAkLPEhxwMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAmBgNVHREEHzAdghttYXNxdWUuY2xvdWRmbGFyZWNsaWVudC5jb20wCgYIKoZIzj0EAwMDaAAwZQIwLS/QI/GHtOvBaf5jYJJtCUrDOITNY0hl7RZMcye4txaJaC2xEs9Nbo673Mku5QLUAjEAlzppJWKclkTTZLoIBRdbyIZnf0nKnGKEoA0kRh6eChPf2n6csMhL1VOVAz1EMgOu"
	testMASQUEPeerPublicKeyPEM  = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n-----END PUBLIC KEY-----"
	testOtherPublicKeyPEM       = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3\na1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzmw==\n-----END PUBLIC KEY-----"
)
