package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/skye-z/amz/internal/storage"
	"github.com/skye-z/amz/internal/testkit"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type transportFunc func(context.Context, TransportRequest) ([]byte, error)

func (f transportFunc) Do(ctx context.Context, req TransportRequest) ([]byte, error) { return f(ctx, req) }

func TestNewServiceValidatesDependencies(t *testing.T) {
	if _, err := NewService(nil, &stubStateStore{}); !errors.Is(err, ErrClientRequired) {
		t.Fatalf("expected ErrClientRequired, got %v", err)
	}
	if _, err := NewService(&stubAuthClient{}, nil); !errors.Is(err, ErrStateStoreRequired) {
		t.Fatalf("expected ErrStateStoreRequired, got %v", err)
	}
}

func TestNewClientValidatesTransport(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, ErrTransportRequired) {
		t.Fatalf("expected ErrTransportRequired, got %v", err)
	}
}

func TestClientRegisterAndEnrollRequests(t *testing.T) {
	client, err := NewClient(transportFunc(func(_ context.Context, req TransportRequest) ([]byte, error) {
		if req.Method == http.MethodPost {
			if req.Path != "/reg" {
				t.Fatalf("expected register path, got %q", req.Path)
			}
			return []byte(`{"id":"dev-1","token":"tok-1"}`), nil
		}
		if req.Method == http.MethodPatch {
			if req.Path != "/reg/dev-1" {
				t.Fatalf("expected enroll path, got %q", req.Path)
			}
			if req.BearerToken != "tok-1" {
				t.Fatalf("expected bearer token, got %q", req.BearerToken)
			}
			return []byte(`{"id":"dev-1","token":"tok-2"}`), nil
		}
		return nil, fmt.Errorf("unexpected method %s", req.Method)
	}))
	if err != nil {
		t.Fatalf("expected client creation success, got %v", err)
	}

	registered, err := client.Register(context.Background(), Request{Key: "pub"})
	if err != nil {
		t.Fatalf("expected register success, got %v", err)
	}
	if registered.ID != "dev-1" || registered.Token != "tok-1" {
		t.Fatalf("unexpected register response: %+v", registered)
	}

	enrolled, err := client.Enroll(context.Background(), "dev-1", "tok-1", EnrollRequest{Key: "pub"})
	if err != nil {
		t.Fatalf("expected enroll success, got %v", err)
	}
	if enrolled.Token != "tok-2" {
		t.Fatalf("unexpected enroll response: %+v", enrolled)
	}
}

func TestClientErrorsWrapMarshalAndTransportFailures(t *testing.T) {
	client, err := NewClient(transportFunc(func(_ context.Context, _ TransportRequest) ([]byte, error) {
		return nil, errors.New("boom")
	}))
	if err != nil {
		t.Fatalf("expected client creation success, got %v", err)
	}
	if _, err := client.Register(context.Background(), Request{Key: "ok"}); err == nil || !strings.Contains(err.Error(), "do register request") {
		t.Fatalf("expected wrapped register transport error, got %v", err)
	}
}

func TestGenerateAndLoadDeviceKeyPair(t *testing.T) {
	pair, err := GenerateDeviceKeyPair(DefaultDeviceKeyType)
	if err != nil {
		t.Fatalf("expected key generation success, got %v", err)
	}
	if pair.PublicKey == "" || pair.PrivateKey == "" {
		t.Fatalf("expected populated key pair: %+v", pair)
	}
	loaded, err := LoadDeviceKeyPair(DefaultDeviceKeyType, pair.PrivateKey)
	if err != nil {
		t.Fatalf("expected key load success, got %v", err)
	}
	if loaded.PublicKey != pair.PublicKey {
		t.Fatalf("expected identical public key, got %q vs %q", loaded.PublicKey, pair.PublicKey)
	}
}

func TestDeviceKeyPairValidationErrors(t *testing.T) {
	if _, err := GenerateDeviceKeyPair("rsa"); !errors.Is(err, ErrUnsupportedDeviceKeyType) {
		t.Fatalf("expected unsupported key type error, got %v", err)
	}
	if _, err := LoadDeviceKeyPair("rsa", "anything"); !errors.Is(err, ErrUnsupportedDeviceKeyType) {
		t.Fatalf("expected unsupported load key type error, got %v", err)
	}
	if _, err := LoadDeviceKeyPair(DefaultDeviceKeyType, "%%%invalid-base64"); err == nil || !strings.Contains(err.Error(), "decode device private key") {
		t.Fatalf("expected decode error, got %v", err)
	}
	bad := base64.StdEncoding.EncodeToString([]byte("not-a-key"))
	if _, err := LoadDeviceKeyPair(DefaultDeviceKeyType, bad); err == nil || !strings.Contains(err.Error(), "parse device private key") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestHTTPTransportBuildsRequestsAndParsesErrors(t *testing.T) {
	transport, err := NewHTTPTransport("https://example.com/", roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://example.com/v0a4471/reg/dev-1" {
			t.Fatalf("unexpected request url: %s", req.URL.String())
		}
		if got := req.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("expected authorization header, got %q", got)
		}
		if got := req.Header.Get("CF-Client-Version"); got == "" {
			t.Fatal("expected default headers to be applied")
		}
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: ioNopCloser(`{"errors":[{"code":1015,"message":"rate limit"}]}`)}, nil
	}))
	if err != nil {
		t.Fatalf("expected transport creation success, got %v", err)
	}
	_, err = transport.Do(context.Background(), TransportRequest{Method: http.MethodPatch, Path: "reg/dev-1", BearerToken: "tok"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Category() != APIErrorCategoryRateLimited {
		t.Fatalf("expected rate-limited API error, got %v", err)
	}
}

func TestHTTPTransportAndParsingHelpers(t *testing.T) {
	if _, err := NewHTTPTransport("", nil); !errors.Is(err, ErrHTTPDoerRequired) {
		t.Fatalf("expected ErrHTTPDoerRequired, got %v", err)
	}
	defaultTransport, err := NewDefaultHTTPTransport()
	if err != nil {
		t.Fatalf("expected default transport success, got %v", err)
	}
	if defaultTransport.baseURL != defaultRegisterBaseURL {
		t.Fatalf("expected default base url, got %q", defaultTransport.baseURL)
	}
	if got := buildRegisterPath(""); got != "/"+defaultRegisterAPIVersion {
		t.Fatalf("unexpected empty path result: %q", got)
	}
	if got := buildRegisterPath("/v0a4471/reg"); got != "/v0a4471/reg" {
		t.Fatalf("unexpected versioned path result: %q", got)
	}
	if got := buildRegisterPath("reg"); got != "/"+defaultRegisterAPIVersion+"/reg" {
		t.Fatalf("unexpected relative path result: %q", got)
	}
	if _, err := ParseResponse([]byte(`{"success":false,"errors":[{"code":1,"message":"bad"}]}`)); err == nil {
		t.Fatal("expected ParseResponse to surface API error")
	}
	if err := parseAPIError(500, []byte(`boom`)); err == nil {
		t.Fatal("expected parseAPIError to return error")
	}
	if extractAPIError(200, []byte(`{"success":true}`)) != nil {
		t.Fatal("expected success envelope to produce nil api error")
	}
}

func TestAPIErrorCategoryClassification(t *testing.T) {
	cases := []struct {
		err  *APIError
		want APIErrorCategory
	}{
		{&APIError{StatusCode: http.StatusUnauthorized}, APIErrorCategoryUnauthorized},
		{&APIError{StatusCode: http.StatusTooManyRequests}, APIErrorCategoryRateLimited},
		{&APIError{StatusCode: http.StatusBadRequest, Message: "invalid payload"}, APIErrorCategoryInvalidRequest},
		{&APIError{StatusCode: http.StatusInternalServerError}, APIErrorCategoryServer},
		{&APIError{StatusCode: 418, Message: "forbidden"}, APIErrorCategoryUnauthorized},
	}
	for _, tt := range cases {
		if got := tt.err.Category(); got != tt.want {
			t.Fatalf("expected %q, got %q for %+v", tt.want, got, tt.err)
		}
	}
	if got := ClassifyAPIError(errors.New("plain")); got != APIErrorCategoryUnknown {
		t.Fatalf("expected unknown for non-api error, got %q", got)
	}
}

func TestModelHelpersAndBuildState(t *testing.T) {
	device := (DeviceIdentity{}).withDefaults()
	if device.Model != DefaultDeviceModel || device.KeyType != DefaultDeviceKeyType || device.TunnelType != DefaultDeviceTunnelType {
		t.Fatalf("expected defaults, got %+v", device)
	}
	pair, err := GenerateDeviceKeyPair(DefaultDeviceKeyType)
	if err != nil {
		t.Fatalf("expected generated pair, got %v", err)
	}
	reg := BuildRegisterRequest(pair, DeviceIdentity{})
	if reg.Type != "Android" || reg.Key != pair.PublicKey || reg.KeyType != DefaultDeviceKeyType {
		t.Fatalf("unexpected register request: %+v", reg)
	}
	enroll := BuildEnrollRequest(pair, DeviceIdentity{})
	if enroll.Key != pair.PublicKey || enroll.TunType != DefaultDeviceTunnelType {
		t.Fatalf("unexpected enroll request: %+v", enroll)
	}
	cert, err := GenerateClientCertificate(pair.PrivateKey)
	if err != nil {
		t.Fatalf("expected client certificate, got %v", err)
	}
	rawCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		t.Fatalf("expected base64 cert, got %v", err)
	}
	if _, err := x509.ParseCertificate(rawCert); err != nil {
		t.Fatalf("expected parsable cert, got %v", err)
	}
	if _, err := GenerateClientCertificate("not-base64"); err == nil {
		t.Fatal("expected invalid private key error")
	}

	previous := storage.State{SelectedNode: "node-keep", NodeCache: []storage.Node{{ID: "node-keep", PublicKey: "old"}}, Interface: storage.InterfaceAddresses{V4: "1.1.1.1"}, Services: storage.Services{HTTPProxy: "http://old"}}
	final := Response{ID: "dev-1", Token: "tok-2", Account: ResponseAccount{Type: "plus", License: "lic"}, Config: ResponseConfig{ClientID: "cid", Interface: ResponseConfigInterface{Addresses: storage.InterfaceAddresses{V6: testkit.WarpIPv6Primary443}}, Services: ResponseConfigServices{HTTPProxy: "http://new"}, Peers: []ResponsePeer{{PublicKey: "pk2", Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Host: testkit.WarpHostPrimary, V4: "1.2.3.4", Ports: []uint16{500}}}}, {PublicKey: "pk1", Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V6: testkit.WarpIPv6Primary443}}}}}}
	state, err := buildState(previous, pair.PrivateKey, "fallback-token", final)
	if err != nil {
		t.Fatalf("expected buildState success, got %v", err)
	}
	if state.Token != "tok-2" || state.Certificate.PeerPublicKey == "" || len(state.NodeCache) != 2 {
		t.Fatalf("unexpected built state: %+v", state)
	}
	if state.SelectedNode != "node-keep" {
		t.Fatalf("expected selected node preserved, got %q", state.SelectedNode)
	}
	if got := normalizePeerEndpoint("2001:db8::1", 443); !strings.HasPrefix(got, "[") {
		t.Fatalf("expected ipv6 endpoint to be bracketed, got %q", got)
	}
	if got := firstNonEmpty("", " a "); got != "a" {
		t.Fatalf("unexpected firstNonEmpty result: %q", got)
	}
	if got := selectPeerPort([]uint16{0, 500}); got != 500 {
		t.Fatalf("unexpected selected port: %d", got)
	}
}

func TestResponseEndpointAndInterfaceUnmarshal(t *testing.T) {
	var endpoint ResponseEndpoint
	if err := endpoint.UnmarshalJSON([]byte(`"host.example:443"`)); err != nil {
		t.Fatalf("expected string endpoint success, got %v", err)
	}
	if endpoint.PreferredAddress() != "host.example:443" {
		t.Fatalf("unexpected preferred address: %q", endpoint.PreferredAddress())
	}
	if err := endpoint.UnmarshalJSON([]byte(`{"host":"api.example","v4":"1.1.1.1","ports":[443]}`)); err != nil {
		t.Fatalf("expected object endpoint success, got %v", err)
	}
	if endpoint.PreferredAddress() != "api.example" {
		t.Fatalf("unexpected preferred object address: %q", endpoint.PreferredAddress())
	}
	if err := endpoint.UnmarshalJSON([]byte(`123`)); err == nil {
		t.Fatal("expected unsupported endpoint payload error")
	}
	var iface ResponseConfigInterface
	if err := iface.UnmarshalJSON([]byte(`{"v4":"1.1.1.1","v6":"::1"}`)); err != nil {
		t.Fatalf("expected flat interface success, got %v", err)
	}
	if iface.Addresses.V4 == "" || iface.Addresses.V6 == "" {
		t.Fatalf("unexpected interface addresses: %+v", iface)
	}
}

func TestServiceErrorBranches(t *testing.T) {
	svc := &Service{client: &stubAuthClient{}, store: &stubStateStore{}, generateKeyPair: func(string) (DeviceKeyPair, error) { return DeviceKeyPair{}, errors.New("gen") }}
	if _, err := svc.register(context.Background(), storage.State{}, DeviceIdentity{}); err == nil || !strings.Contains(err.Error(), "generate device key pair") {
		t.Fatalf("expected register generate error, got %v", err)
	}
	svc = &Service{client: &stubAuthClient{}, store: &stubStateStore{}, loadKeyPair: func(string, string) (DeviceKeyPair, error) { return DeviceKeyPair{}, errors.New("load") }}
	if _, err := svc.reuse(context.Background(), storage.State{DeviceID: "id", Token: "tok", Certificate: storage.Certificate{PrivateKey: "priv"}}, DeviceIdentity{}); err == nil || !strings.Contains(err.Error(), "reuse device credentials") {
		t.Fatalf("expected reuse load error, got %v", err)
	}
	if !shouldRegisterFallback(ErrIncompleteStoredState) {
		t.Fatal("expected incomplete state to fallback")
	}
	if !shouldRegisterFallback(ErrUnsupportedDeviceKeyType) {
		t.Fatal("expected unsupported key type to fallback")
	}
	if shouldRegisterFallback(errors.New("other")) {
		t.Fatal("expected generic error not to fallback")
	}
}

func TestAuthHelperBranchesAndFormatting(t *testing.T) {
	if svc, err := NewService(&stubAuthClient{}, &stubStateStore{}); err != nil || svc == nil {
		t.Fatalf("expected NewService success, got svc=%v err=%v", svc, err)
	}
	if svc, err := NewDefaultService(""); err != nil || svc == nil {
		t.Fatalf("expected NewDefaultService success, got svc=%v err=%v", svc, err)
	}

	if got := (&APIError{StatusCode: 400, Code: 7, Message: "bad"}).Error(); !strings.Contains(got, "code=7") {
		t.Fatalf("unexpected api error string: %q", got)
	}
	if got := (&APIError{StatusCode: 400, Message: "bad"}).Error(); !strings.Contains(got, "message=bad") {
		t.Fatalf("unexpected api error string: %q", got)
	}
	if got := (&APIError{StatusCode: 400}).Error(); !strings.Contains(got, "status=400") {
		t.Fatalf("unexpected api error string: %q", got)
	}
	var nilAPI *APIError
	if got := nilAPI.Error(); got == "" {
		t.Fatal("expected nil api error string")
	}

	if got := (&APIError{StatusCode: 418, Message: "unknown"}).Category(); got != APIErrorCategoryUnknown {
		t.Fatalf("expected unknown api category, got %q", got)
	}
	if got := (&APIError{StatusCode: 418, Message: "too many requests"}).Category(); got != APIErrorCategoryRateLimited {
		t.Fatalf("expected rate limited api category, got %q", got)
	}

	if err := parseAPIError(500, nil); err == nil {
		t.Fatal("expected parseAPIError fallback error")
	}
	if apiErr := extractAPIError(500, []byte(`{"messages":["hello"]}`)); apiErr == nil || apiErr.Message != "hello" {
		t.Fatalf("expected messages api error, got %+v", apiErr)
	}
	if apiErr := extractAPIError(500, []byte(`{"error":"plain-error"}`)); apiErr == nil || apiErr.Message != "plain-error" {
		t.Fatalf("expected plain error api error, got %+v", apiErr)
	}
	if apiErr := extractAPIError(500, []byte(`{"reason":"plain-reason"}`)); apiErr == nil || apiErr.Message != "plain-reason" {
		t.Fatalf("expected reason api error, got %+v", apiErr)
	}
	if apiErr := extractAPIError(500, []byte(`{}`)); apiErr == nil {
		t.Fatal("expected fallback api error on empty error envelope")
	}

	endpoint := ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: "1.1.1.1", V6: "::1", Addr: "raw"}}
	if got := endpoint.PreferredAddress(); got != "1.1.1.1" {
		t.Fatalf("unexpected preferred address: %q", got)
	}
	endpoint = ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V6: "::1", Addr: "raw"}}
	if got := endpoint.PreferredAddress(); got != "::1" {
		t.Fatalf("unexpected preferred ipv6 address: %q", got)
	}
	endpoint = ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Addr: "raw"}}
	if got := endpoint.PreferredAddress(); got != "raw" {
		t.Fatalf("unexpected preferred raw address: %q", got)
	}

	if got := buildNodeID(ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Host: "host"}}}); got != "host" {
		t.Fatalf("unexpected node id from host: %q", got)
	}
	if got := buildNodeID(ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: "1.1.1.1", Ports: []uint16{443}}}}); got == "" {
		t.Fatal("expected node id from ipv4 endpoint")
	}
	if got := comparePeer(
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Host: "host", V4: "1.1.1.1", Ports: []uint16{443}}}},
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: "1.1.1.2"}}},
	); got <= 0 {
		t.Fatalf("expected richer peer to compare greater, got %d", got)
	}
	if got := comparePeer(
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: "1.1.1.1"}}},
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: "1.1.1.2"}}},
	); got >= 0 {
		t.Fatalf("expected lexical compare ordering, got %d", got)
	}
}

func ioNopCloser(body string) *readCloser { return &readCloser{Reader: strings.NewReader(body)} }

type readCloser struct{ *strings.Reader }

func (r *readCloser) Close() error { return nil }
