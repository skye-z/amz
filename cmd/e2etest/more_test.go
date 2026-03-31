package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchIPSuccessAndHeaders(t *testing.T) {
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != ipAPI {
			t.Fatalf("unexpected url: %s", req.URL.String())
		}
		if got := req.Header.Get("User-Agent"); got != "amz-e2etest/1.0" {
			t.Fatalf("unexpected user-agent: %q", got)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ip":"1.2.3.4","city":"A","country":"B","connection":{"org":"C"}}`))}, nil
	})
	ip, raw, err := fetchIP(context.Background(), transport)
	if err != nil {
		t.Fatalf("expected fetch success, got %v", err)
	}
	if ip != "1.2.3.4" || raw["ip"].(string) != "1.2.3.4" {
		t.Fatalf("unexpected fetch result: %s %+v", ip, raw)
	}
}

func TestFetchIPErrorBranches(t *testing.T) {
	cases := []struct {
		name string
		rt   http.RoundTripper
	}{
		{name: "request error", rt: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("boom") })},
		{name: "bad json", rt: roundTripperFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`oops`))}, nil })},
		{name: "missing ip", rt: roundTripperFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"country":"x"}`))}, nil })},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := fetchIP(context.Background(), tt.rt); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestProxyTransportHelpersAndLogger(t *testing.T) {
	httpTransport := httpProxyTransport("127.0.0.1:8080")
	if httpTransport == nil || httpTransport.Proxy == nil {
		t.Fatal("expected http proxy transport with proxy func")
	}
	socksTransport, err := socks5ProxyTransport("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("expected socks transport creation success, got %v", err)
	}
	if socksTransport == nil {
		t.Fatal("expected socks transport")
	}
	var buf bytes.Buffer
	logger := newAMZLogger(&buf)
	logger.Printf("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Fatalf("expected logger output, got %q", buf.String())
	}
}

func TestPrintHelpers(t *testing.T) {
	oldStdout := captureStdout(t)
	oldStderr := captureStderr(t)
	printBanner("Banner")
	printStep(2, "Step")
	printInfo("info %s", "x")
	printPass("pass %s", "x")
	printFail("fail %s", "x")
	printIPInfo("TAG", "1.1.1.1", map[string]any{"city": "A", "country": "B", "org": "C"})
	stdout := oldStdout()
	stderr := oldStderr()
	if !strings.Contains(stdout, "Banner") || !strings.Contains(stdout, "[PASS]") || !strings.Contains(stdout, "[TAG] IP") {
		t.Fatalf("unexpected stdout: %s", stdout)
	}
	if !strings.Contains(stderr, "[FAIL]") {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}

func captureStdout(t *testing.T) func() string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("expected stdout pipe success, got %v", err)
	}
	os.Stdout = w
	return func() string {
		_ = w.Close()
		os.Stdout = old
		data, _ := io.ReadAll(r)
		_ = r.Close()
		return string(data)
	}
}

func captureStderr(t *testing.T) func() string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("expected stderr pipe success, got %v", err)
	}
	os.Stderr = w
	return func() string {
		_ = w.Close()
		os.Stderr = old
		data, _ := io.ReadAll(r)
		_ = r.Close()
		return string(data)
	}
}
