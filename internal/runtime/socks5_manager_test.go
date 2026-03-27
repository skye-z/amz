package runtime

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestEncodeSOCKSAddressSupportsIPv4DomainAndIPv6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		atyp    byte
		check   func(*testing.T, []byte)
	}{
		{
			name:    "ipv4",
			address: "1.2.3.4:53",
			atyp:    socksAtypIPv4,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				if got := net.IP(encoded[1:5]).String(); got != "1.2.3.4" {
					t.Fatalf("expected ipv4 host 1.2.3.4, got %q", got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[5:7])); got != 53 {
					t.Fatalf("expected ipv4 port 53, got %d", got)
				}
			},
		},
		{
			name:    "domain",
			address: "example.com:443",
			atyp:    socksAtypDomain,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				hostLen := int(encoded[1])
				if got := string(encoded[2 : 2+hostLen]); got != "example.com" {
					t.Fatalf("expected domain host example.com, got %q", got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[2+hostLen:])); got != 443 {
					t.Fatalf("expected domain port 443, got %d", got)
				}
			},
		},
		{
			name:    "ipv6",
			address: "[2001:db8::1]:8443",
			atyp:    socksAtypIPv6,
			check: func(t *testing.T, encoded []byte) {
				t.Helper()
				if got := net.IP(encoded[1:17]).String(); got != "2001:db8::1" {
					t.Fatalf("expected ipv6 host 2001:db8::1, got %q", got)
				}
				if got := int(binary.BigEndian.Uint16(encoded[17:19])); got != 8443 {
					t.Fatalf("expected ipv6 port 8443, got %d", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := encodeSOCKSAddress(tt.address)
			if err != nil {
				t.Fatalf("expected encode success, got %v", err)
			}
			if encoded[0] != tt.atyp {
				t.Fatalf("expected atyp %#x, got %#x", tt.atyp, encoded[0])
			}
			tt.check(t, encoded)
		})
	}
}

func TestBuildAndParseSOCKSUDPDatagramRoundTrip(t *testing.T) {
	t.Parallel()

	address := "8.8.8.8:53"
	payload := []byte("dns-query")

	packet, err := buildSOCKSUDPDatagram(address, payload)
	if err != nil {
		t.Fatalf("expected build success, got %v", err)
	}
	if !bytes.Equal(packet[:3], []byte{0x00, 0x00, 0x00}) {
		t.Fatalf("expected reserved header prefix, got %v", packet[:3])
	}

	target, gotPayload, err := parseSOCKSUDPDatagram(packet)
	if err != nil {
		t.Fatalf("expected parse success, got %v", err)
	}
	if target != address {
		t.Fatalf("expected target %q, got %q", address, target)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("expected payload %q, got %q", string(payload), string(gotPayload))
	}
}

func TestEncodeSOCKSAddressRejectsOutOfRangePorts(t *testing.T) {
	t.Parallel()

	tests := []string{
		"1.2.3.4:-1",
		"1.2.3.4:65536",
		"example.com:70000",
	}

	for _, address := range tests {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()

			if _, err := encodeSOCKSAddress(address); err == nil {
				t.Fatalf("expected out-of-range port error for %q", address)
			}
		})
	}
}
