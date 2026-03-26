package runtime

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type upstreamConnectDialer struct {
	base     contextDialer
	upstream string
}

func newUpstreamConnectDialer(base contextDialer, upstream string) *upstreamConnectDialer {
	return &upstreamConnectDialer{
		base:     base,
		upstream: strings.TrimSpace(upstream),
	}
}

func (d *upstreamConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.base == nil {
		return nil, fmt.Errorf("upstream proxy dialer is unavailable")
	}
	conn, err := d.base.DialContext(ctx, network, d.upstream)
	if err != nil {
		return nil, err
	}
	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: address},
		Host:   address,
		Header: make(http.Header),
	}).WithContext(ctx)
	req.Header.Set("Proxy-Connection", "keep-alive")
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write upstream CONNECT request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream CONNECT response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("upstream CONNECT rejected: status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	return conn, nil
}

func (d *upstreamConnectDialer) Close() error {
	if closer, ok := d.base.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func newUpstreamHTTPTransport(upstream string, dialer contextDialer) http.RoundTripper {
	if dialer == nil {
		return nil
	}
	proxyURL := &url.URL{Scheme: "http", Host: strings.TrimSpace(upstream)}
	return &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// dnsResolvingDialer resolves hostnames to IPs before passing to the
// underlying PacketStackDialer which only accepts IP literals.
type dnsResolvingDialer struct {
	base contextDialer
}

func newDNSResolvingDialer(base contextDialer) *dnsResolvingDialer {
	return &dnsResolvingDialer{base: base}
}

// NewExportedDNSResolvingDialer is the exported version for use in sdk_runtime.go.
func NewExportedDNSResolvingDialer(base contextDialer) *dnsResolvingDialer {
	return &dnsResolvingDialer{base: base}
}

func (d *dnsResolvingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for %s", host)
		}
		host = ips[0].IP.String()
	}
	return d.base.DialContext(ctx, network, net.JoinHostPort(host, port))
}

func (d *dnsResolvingDialer) Close() error {
	if closer, ok := d.base.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
