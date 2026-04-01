// Command e2etest performs a full-chain integration test of the amz SDK.
//
// It verifies: registration -> node selection -> WARP connect -> HTTP proxy -> SOCKS5 proxy -> TUN
// by comparing the exit IP before and after proxying / tunneling through WARP.
package main

import (
	"context"
	"encoding/json"
	"errors"
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

type transportRoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
}

type clientRuntime interface {
	Start(context.Context) error
	Close() error
	Status() amz.Status
}

type runConfig struct {
	listen    string
	statePath string
	endpoint  string
	timeout   time.Duration
	runHTTP   bool
	runSOCKS5 bool
	runTUN    bool
}

type runDeps struct {
	fetchIP   func(context.Context, transportRoundTripper) (string, map[string]any, error)
	newClient func(amz.Options) (clientRuntime, error)
	sleep     func(time.Duration)
}

func defaultRunDeps() runDeps {
	return runDeps{
		fetchIP: fetchIP,
		newClient: func(opts amz.Options) (clientRuntime, error) {
			return amz.NewClient(opts)
		},
		sleep: time.Sleep,
	}
}

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
	os.Exit(runE2E(runConfig{
		listen:    *listen,
		statePath: *statePath,
		endpoint:  *endpoint,
		timeout:   *timeout,
		runHTTP:   runHTTP,
		runSOCKS5: runSOCKS5,
		runTUN:    runTUN,
	}, defaultRunDeps()))
}

func runE2E(cfg runConfig, deps runDeps) int {
	deps = normalizeRunDeps(deps)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	printBanner("AMZ Full-Chain E2E Test")
	directIP, err := printDirectIPStep(ctx, deps)
	if err != nil {
		return 1
	}

	logger := newAMZLogger(os.Stdout)
	client, proxyAddr, err := startPrimaryClient(ctx, cfg, deps, logger)
	if err != nil {
		return 1
	}
	defer client.Close()
	deps.sleep(500 * time.Millisecond)

	summary := e2eSummary{passed: true}
	step := 3
	if cfg.runHTTP {
		summary.httpProxyIP, summary.passed = runHTTPCheck(ctx, deps, proxyAddr, directIP, summary.passed, step)
		step++
	}
	if cfg.runSOCKS5 {
		summary.socksProxyIP, summary.passed = runSOCKS5Check(ctx, deps, proxyAddr, directIP, summary.passed, step)
		step++
	}
	if cfg.runTUN {
		summary.tunIP, summary.passed = runTUNCheck(ctx, cfg, deps, logger, client, directIP, summary.passed, step)
	}

	printE2ESummary(directIP, summary)
	if summary.passed {
		printPass("=== ALL TESTS PASSED ===")
		return 0
	}
	printFail("=== SOME TESTS FAILED ===")
	return 1
}

type e2eSummary struct {
	passed       bool
	httpProxyIP  string
	socksProxyIP string
	tunIP        string
}

func normalizeRunDeps(deps runDeps) runDeps {
	defaultDeps := defaultRunDeps()
	if deps.fetchIP == nil {
		deps.fetchIP = defaultDeps.fetchIP
	}
	if deps.newClient == nil {
		deps.newClient = defaultDeps.newClient
	}
	if deps.sleep == nil {
		deps.sleep = defaultDeps.sleep
	}
	return deps
}

func printDirectIPStep(ctx context.Context, deps runDeps) (string, error) {
	directIP, directRaw, err := deps.fetchIP(ctx, nil)
	if err != nil {
		printFail("Failed to get direct IP: %v", err)
		return "", err
	}
	printStep(1, "Fetching direct exit IP (no proxy)")
	printIPInfo(tagDirect, directIP, directRaw)
	return directIP, nil
}

func startPrimaryClient(ctx context.Context, cfg runConfig, deps runDeps, logger amz.Logger) (clientRuntime, string, error) {
	opts := buildClientOptionsForModes(cfg.listen, cfg.statePath, cfg.endpoint, logger, cfg.runHTTP, cfg.runSOCKS5, false)
	if cfg.endpoint != "" {
		printInfo("  Using fixed endpoint: %s", cfg.endpoint)
	}
	client, err := deps.newClient(opts)
	if err != nil {
		printFail("Failed to create client: %v", err)
		return nil, "", err
	}
	status, elapsed, err := startClient(ctx, client)
	if err != nil {
		return nil, "", err
	}
	printClientStatus(status, elapsed)
	return client, resolveProxyAddress(status, cfg.listen), nil
}

func startClient(ctx context.Context, client clientRuntime) (amz.Status, time.Duration, error) {
	startTime := time.Now()
	if err := client.Start(ctx); err != nil {
		printFail("Failed to start client: %v", err)
		return amz.Status{}, 0, err
	}
	status := client.Status()
	if !status.Running {
		printFail("Client is not running after Start()")
		return amz.Status{}, 0, errors.New("client not running after start")
	}
	return status, time.Since(startTime), nil
}

func printClientStatus(status amz.Status, elapsed time.Duration) {
	printStep(2, "Starting amz client (register -> node select -> connect WARP)")
	printInfo("  Started in:      %s", elapsed.Round(time.Millisecond))
	printInfo("  Running:         %v", status.Running)
	printInfo("  Listen address:  %s", status.ListenAddress)
	printInfo("  Endpoint:        %s", status.Endpoint)
	printInfo("  Registered:      %v", status.Registered)
	printInfo("  HTTP enabled:    %v", status.HTTPEnabled)
	printInfo("  SOCKS5 enabled:  %v", status.SOCKS5Enabled)
	printInfo("  TUN enabled:     %v", status.TUNEnabled)
}

func resolveProxyAddress(status amz.Status, fallback string) string {
	if status.ListenAddress != "" {
		return status.ListenAddress
	}
	return fallback
}

func runHTTPCheck(ctx context.Context, deps runDeps, proxyAddr, directIP string, passed bool, step int) (string, bool) {
	printStep(step, "Fetching exit IP via HTTP proxy")
	ip, ok := runProxyCheck(ctx, deps, tagHTTP, directIP, httpProxyTransport(proxyAddr), "HTTP proxy request failed: %v", "HTTP proxy IP is the same as direct IP (%s) -- tunnel not working!", "HTTP proxy IP (%s) differs from direct IP (%s)")
	return ip, passed && ok
}

func runSOCKS5Check(ctx context.Context, deps runDeps, proxyAddr, directIP string, passed bool, step int) (string, bool) {
	printStep(step, "Fetching exit IP via SOCKS5 proxy")
	transport, err := socks5ProxyTransport(proxyAddr)
	if err != nil {
		printFail("Failed to create SOCKS5 transport: %v", err)
		return "", false
	}
	ip, ok := runProxyCheck(ctx, deps, tagSOCKS5, directIP, transport, "SOCKS5 proxy request failed: %v", "SOCKS5 proxy IP is the same as direct IP (%s) -- tunnel not working!", "SOCKS5 proxy IP (%s) differs from direct IP (%s)")
	return ip, passed && ok
}

func runProxyCheck(ctx context.Context, deps runDeps, tag, directIP string, transport transportRoundTripper, requestErrFmt, sameIPFmt, diffIPFmt string) (string, bool) {
	ip, raw, err := deps.fetchIP(ctx, transport)
	if err != nil {
		printFail(requestErrFmt, err)
		return "", false
	}
	printIPInfo(tag, ip, raw)
	if ip == directIP {
		printFail(sameIPFmt, ip)
		return ip, false
	}
	printPass(diffIPFmt, ip, directIP)
	return ip, true
}

func runTUNCheck(ctx context.Context, cfg runConfig, deps runDeps, logger amz.Logger, client clientRuntime, directIP string, passed bool, step int) (string, bool) {
	printStep(step, "Fetching exit IP via TUN")
	_ = client.Close()

	tunClient, err := deps.newClient(buildClientOptionsForModes("", cfg.statePath+".tun", cfg.endpoint, logger, false, false, true))
	if err != nil {
		printFail("Failed to create TUN client: %v", err)
		return "", false
	}
	defer tunClient.Close()
	if err := tunClient.Start(ctx); err != nil {
		printFail("TUN start failed: %v", err)
		return "", false
	}
	deps.sleep(2 * time.Second)
	ip, raw, err := deps.fetchIP(ctx, nil)
	if err != nil {
		printFail("TUN request failed: %v", err)
		return "", false
	}
	printIPInfo(tagTUN, ip, raw)
	if ip == directIP {
		printFail("TUN IP is the same as direct IP (%s) -- tunnel not working!", ip)
		return ip, false
	}
	printPass("TUN IP (%s) differs from direct IP (%s)", ip, directIP)
	return ip, passed
}

func printE2ESummary(directIP string, summary e2eSummary) {
	printBanner("Test Summary")
	fmt.Printf("  Direct IP:  %s\n", directIP)
	if summary.httpProxyIP != "" {
		fmt.Printf("  HTTP IP:    %s\n", summary.httpProxyIP)
	}
	if summary.socksProxyIP != "" {
		fmt.Printf("  SOCKS5 IP:  %s\n", summary.socksProxyIP)
	}
	if summary.tunIP != "" {
		fmt.Printf("  TUN IP:     %s\n", summary.tunIP)
	}
	fmt.Println()
}

func fetchIP(ctx context.Context, transport transportRoundTripper) (string, map[string]any, error) {
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
