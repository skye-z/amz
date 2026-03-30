// Command e2etest performs a full-chain integration test of the amz SDK.
//
// It verifies: registration -> node selection -> WARP connect -> HTTP proxy -> SOCKS5 proxy -> TUN
// by comparing the exit IP before and after proxying / tunneling through WARP.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/skye-z/amz"
	"golang.org/x/net/proxy"
)

const ipAPI = "https://ipwho.is/"

const (
	tagDirect = "DIRECT"
	tagHTTP   = "HTTP_PROXY"
	tagSOCKS5 = "SOCKS5_PROXY"
	tagTUN    = "TUN"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:19811", "proxy listen address")
	statePath := flag.String("state", "./e2etest_state.json", "path for amz state file")
	endpoint := flag.String("endpoint", "", "override WARP endpoint (e.g. 162.159.198.1:443)")
	timeout := flag.Duration("timeout", 120*time.Second, "total test timeout")
	skipHTTP := flag.Bool("skip-http", false, "skip http proxy verification")
	skipSOCKS5 := flag.Bool("skip-socks5", false, "skip socks5 proxy verification")
	skipTUN := flag.Bool("skip-tun", false, "skip tun verification")
	flag.Parse()

	runHTTP, runSOCKS5, runTUN := shouldRunModes(*skipHTTP, *skipSOCKS5, *skipTUN)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	passed := true
	var httpProxyIP, socksProxyIP, tunIP string

	printBanner("AMZ Full-Chain E2E Test")

	directIP, directRaw, err := fetchIP(ctx, nil)
	if err != nil {
		printFail("Failed to get direct IP: %v", err)
		os.Exit(1)
	}
	printStep(1, "Fetching direct exit IP (no proxy)")
	printIPInfo(tagDirect, directIP, directRaw)

	logger := newAMZLogger(os.Stdout)
	opts := buildClientOptionsForModes(*listen, *statePath, *endpoint, logger, runHTTP, runSOCKS5, false)
	if *endpoint != "" {
		printInfo("  Using fixed endpoint: %s", *endpoint)
	}
	client, err := amz.NewClient(opts)
	if err != nil {
		printFail("Failed to create client: %v", err)
		os.Exit(1)
	}
	defer client.Close()

	startTime := time.Now()
	if err := client.Start(ctx); err != nil {
		printFail("Failed to start client: %v", err)
		os.Exit(1)
	}
	elapsed := time.Since(startTime)

	printStep(2, "Starting amz client (register -> node select -> connect WARP)")
	status := client.Status()
	printInfo("  Started in:      %s", elapsed.Round(time.Millisecond))
	printInfo("  Running:         %v", status.Running)
	printInfo("  Listen address:  %s", status.ListenAddress)
	printInfo("  Endpoint:        %s", status.Endpoint)
	printInfo("  Registered:      %v", status.Registered)
	printInfo("  HTTP enabled:    %v", status.HTTPEnabled)
	printInfo("  SOCKS5 enabled:  %v", status.SOCKS5Enabled)
	printInfo("  TUN enabled:     %v", status.TUNEnabled)

	if !status.Running {
		printFail("Client is not running after Start()")
		os.Exit(1)
	}

	proxyAddr := status.ListenAddress
	if proxyAddr == "" {
		proxyAddr = *listen
	}

	time.Sleep(500 * time.Millisecond)

	step := 3
	if runHTTP {
		printStep(step, "Fetching exit IP via HTTP proxy")
		httpTransport := httpProxyTransport(proxyAddr)
		ip, raw, err := fetchIP(ctx, httpTransport)
		if err != nil {
			printFail("HTTP proxy request failed: %v", err)
			passed = false
		} else {
			httpProxyIP = ip
			printIPInfo(tagHTTP, ip, raw)
			if ip == directIP {
				printFail("HTTP proxy IP is the same as direct IP (%s) -- tunnel not working!", ip)
				passed = false
			} else {
				printPass("HTTP proxy IP (%s) differs from direct IP (%s)", ip, directIP)
			}
		}
		step++
	}

	if runSOCKS5 {
		printStep(step, "Fetching exit IP via SOCKS5 proxy")
		socksTransport, err := socks5ProxyTransport(proxyAddr)
		if err != nil {
			printFail("Failed to create SOCKS5 transport: %v", err)
			passed = false
		} else {
			ip, raw, err := fetchIP(ctx, socksTransport)
			if err != nil {
				printFail("SOCKS5 proxy request failed: %v", err)
				passed = false
			} else {
				socksProxyIP = ip
				printIPInfo(tagSOCKS5, ip, raw)
				if ip == directIP {
					printFail("SOCKS5 proxy IP is the same as direct IP (%s) -- tunnel not working!", ip)
					passed = false
				} else {
					printPass("SOCKS5 proxy IP (%s) differs from direct IP (%s)", ip, directIP)
				}
			}
		}
		step++
	}

	if runTUN {
		printStep(step, "Fetching exit IP via TUN")
		_ = client.Close()

		tunOpts := buildClientOptionsForModes("", *statePath+".tun", *endpoint, logger, false, false, true)
		tunClient, err := amz.NewClient(tunOpts)
		if err != nil {
			printFail("Failed to create TUN client: %v", err)
			passed = false
		} else {
			func() {
				defer tunClient.Close()
				if err := tunClient.Start(ctx); err != nil {
					printFail("TUN start failed: %v", err)
					passed = false
					return
				}
				time.Sleep(2 * time.Second)
				ip, raw, err := fetchIP(ctx, nil)
				if err != nil {
					printFail("TUN request failed: %v", err)
					passed = false
					return
				}
				tunIP = ip
				printIPInfo(tagTUN, ip, raw)
				if ip == directIP {
					printFail("TUN IP is the same as direct IP (%s) -- tunnel not working!", ip)
					passed = false
				} else {
					printPass("TUN IP (%s) differs from direct IP (%s)", ip, directIP)
				}
			}()
		}
	}

	printBanner("Test Summary")
	fmt.Printf("  Direct IP:  %s\n", directIP)
	if httpProxyIP != "" {
		fmt.Printf("  HTTP IP:    %s\n", httpProxyIP)
	}
	if socksProxyIP != "" {
		fmt.Printf("  SOCKS5 IP:  %s\n", socksProxyIP)
	}
	if tunIP != "" {
		fmt.Printf("  TUN IP:     %s\n", tunIP)
	}
	fmt.Println()

	if passed {
		printPass("=== ALL TESTS PASSED ===")
	} else {
		printFail("=== SOME TESTS FAILED ===")
		os.Exit(1)
	}
}

func fetchIP(ctx context.Context, transport http.RoundTripper) (string, map[string]any, error) {
	if transport == nil {
		transport = defaultIPTransport()
	}
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipAPI, nil)
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "amz-e2etest/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", nil, fmt.Errorf("read body: %w", err)
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", nil, fmt.Errorf("parse JSON: %w (body: %s)", err, string(body))
	}

	ipStr, _ := data["ip"].(string)
	if ipStr == "" {
		return "", nil, fmt.Errorf("no 'ip' field in response: %s", string(body))
	}

	return ipStr, data, nil
}

func defaultIPTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		IdleConnTimeout:     0,
	}
}

func httpProxyTransport(proxyAddr string) *http.Transport {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
}

func socks5ProxyTransport(proxyAddr string) (*http.Transport, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return &http.Transport{
			Dial: dialer.Dial,
		}, nil
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return contextDialer.DialContext(ctx, network, addr)
		},
	}, nil
}

func buildClientOptions(listen, statePath, endpoint string, logger amz.Logger) amz.Options {
	return buildClientOptionsForModes(listen, statePath, endpoint, logger, true, true, false)
}

func buildClientOptionsForModes(listen, statePath, endpoint string, logger amz.Logger, httpEnabled, socksEnabled, tunEnabled bool) amz.Options {
	opts := amz.Options{
		Storage: amz.StorageOptions{Path: statePath},
		Listen:  amz.ListenOptions{Address: listen},
		HTTP:    amz.HTTPOptions{Enabled: httpEnabled},
		SOCKS5:  amz.SOCKS5Options{Enabled: socksEnabled},
		TUN:     amz.TUNOptions{Enabled: tunEnabled},
		Logger:  logger,
	}
	if endpoint != "" {
		opts.Transport = amz.TransportOptions{Endpoint: endpoint}
	}
	return opts
}

func shouldRunModes(skipHTTP, skipSOCKS5, skipTUN bool) (bool, bool, bool) {
	return !skipHTTP, !skipSOCKS5, !skipTUN
}

func newAMZLogger(w io.Writer) amz.Logger {
	return log.New(w, "", 0)
}

func printBanner(title string) {
	line := strings.Repeat("=", 60)
	fmt.Printf("\n%s\n  %s\n%s\n\n", line, title, line)
}

func printStep(n int, msg string) {
	fmt.Printf("-- Step %d: %s --\n", n, msg)
}

func printInfo(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func printPass(format string, args ...any) {
	fmt.Printf("  [PASS] "+format+"\n", args...)
}

func printFail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  [FAIL] "+format+"\n", args...)
}

func printIPInfo(tag string, ip string, raw map[string]any) {
	country, _ := raw["country"].(string)
	city, _ := raw["city"].(string)
	org, _ := raw["org"].(string)
	if org == "" {
		if conn, ok := raw["connection"].(map[string]any); ok {
			org, _ = conn["org"].(string)
			if org == "" {
				org, _ = conn["isp"].(string)
			}
		}
	}

	fmt.Printf("  [%s] IP: %s\n", tag, ip)
	if country != "" || city != "" {
		fmt.Printf("  [%s] Location: %s, %s\n", tag, city, country)
	}
	if org != "" {
		fmt.Printf("  [%s] Org: %s\n", tag, org)
	}
}
