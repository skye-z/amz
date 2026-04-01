package amz

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/skye-z/amz/internal/discovery"
	"github.com/skye-z/amz/internal/storage"
)

var detectIPv6Support = defaultDetectIPv6Support

var (
	discoveryScanRangeV4 = net.IPv4(162, 159, 192, 0).String() + "/24"
	discoveryScanRangeV6 = netip.PrefixFrom(netip.AddrFrom16([16]byte{
		0x26, 0x06, 0x47, 0x00, 0x01, 0x03,
	}), 64).String()
	ipv6ConnectivityProbeTarget = net.JoinHostPort(netip.AddrFrom16([16]byte{
		0x26, 0x06, 0x47, 0x00, 0x47, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x11, 0x11,
	}).String(), "53")
)

func buildDiscoveryInput(state storage.State, ipv6Supported bool) discovery.Input {
	input := discovery.Input{
		Registration: registrationFromState(state),
		Cache:        cacheFromState(state),
		Scan: discovery.Scan{
			Source: "auto",
			Range4: []string{discoveryScanRangeV4},
			Range6: []string{discoveryScanRangeV6},
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
	return hasGlobalIPv6Interface() && canDialIPv6Probe()
}

func hasGlobalIPv6Interface() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if interfaceHasGlobalIPv6(iface) {
			return true
		}
	}
	return false
}

func interfaceHasGlobalIPv6(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if isRoutableGlobalIPv6(addrIP(addr)) {
			return true
		}
	}
	return false
}

func addrIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func isRoutableGlobalIPv6(ip net.IP) bool {
	return ip != nil &&
		ip.To4() == nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast()
}

func canDialIPv6Probe() bool {
	conn, err := net.DialTimeout("udp6", ipv6ConnectivityProbeTarget, 300*time.Millisecond)
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
