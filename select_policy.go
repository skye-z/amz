package amz

import (
	"net"
	"strings"
	"time"

	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/storage"
)

var detectIPv6Support = defaultDetectIPv6Support

func buildDiscoveryInput(state storage.State, ipv6Supported bool) discovery.Input {
	input := discovery.Input{
		Registration: registrationFromState(state),
		Cache:        cacheFromState(state),
		Scan: discovery.Scan{
			Source: "auto",
			Range4: []string{"162.159.192.0/24"},
			Range6: []string{"2606:4700:103::/64"},
		},
	}
	if !ipv6Supported {
		input.Registration.EndpointV6 = ""
		input.Scan.Range6 = nil
	}
	return input
}

func filterCandidatesByIPv6Support(candidates []discovery.Candidate, ipv6Supported bool) []discovery.Candidate {
	if ipv6Supported {
		return append([]discovery.Candidate(nil), candidates...)
	}
	filtered := make([]discovery.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if isIPv6LiteralEndpoint(candidate.Address) {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
}

func defaultDetectIPv6Support() bool {
	hasGlobalIPv6 := false
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.To4() != nil {
				continue
			}
			if !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			hasGlobalIPv6 = true
			break
		}
		if hasGlobalIPv6 {
			break
		}
	}
	if !hasGlobalIPv6 {
		return false
	}

	conn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 300*time.Millisecond)
	if err != nil {
		return false
	}
	if conn != nil {
		_ = conn.Close()
	}
	return true
}

func isIPv6LiteralEndpoint(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}
