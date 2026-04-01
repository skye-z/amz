package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/skye-z/amz/internal/storage"
	"github.com/skye-z/amz/internal/testkit"
)

const (
	testAuthDeviceID             = "device-123"
	testAuthAccountID            = "account-123"
	testAuthLicense              = "license-123"
	testAuthTokenRegister        = "token-register"
	testAuthTokenEnrolled        = "token-enrolled"
	testAuthAccountTypePlus      = "plus"
	testAuthAccountStateRegister = "registered"
	testAuthClientID             = "client-id-123"
	testAuthPeerPublicKey        = "peer-public-key-123"
	testAuthRegisterDeviceID     = "dev-1"
	testAuthRegisterToken        = "tok-1"
	testAuthEnrollToken          = "tok-2"
	testAuthSelectedNode         = "node-keep"
	testAuthReplacementDeviceID  = "device-new"
	testAuthIPv4Addr             = testkit.PublicDNSV4
	testAuthIPv4AltAddr          = testkit.TestIPv4Echo
	testAuthIPv6Addr             = testkit.TestIPv6Doc
	testAuthHost                 = "host"
	testAuthTransportBaseURL     = "https://example.com/"
	testAuthTransportRequestURL  = "https://example.com/v0a4471/reg/dev-1"
	testDevicePrivateKeyBase64   = "MHcCAQEEIP2wC9ZwTe74MkRUYw35vj0IadB1iKsFcfoTmyaKOAqvoAoGCCqGSM49AwEHoUQDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzmw=="
	errUnexpectedAPIErrorString  = "unexpected api error string: %q"
)

func TestServiceEnsureRegistersWhenStateMissing(t *testing.T) {
	store := &stubStateStore{loadErr: os.ErrNotExist}
	client := &stubAuthClient{
		registerResponse: Response{
			ID:    testAuthDeviceID,
			Token: testAuthTokenRegister,
			Account: ResponseAccount{
				ID:   testAuthAccountID,
				Type: "free",
			},
		},
		enrollResponse: Response{
			ID:    testAuthDeviceID,
			Token: testAuthTokenEnrolled,
			Account: ResponseAccount{
				ID:      testAuthAccountID,
				Type:    testAuthAccountTypePlus,
				License: testAuthLicense,
			},
			Config: ResponseConfig{
				ClientID: testAuthClientID,
				Peers: []ResponsePeer{{
					PublicKey: testAuthPeerPublicKey,
					Endpoint: ResponseEndpoint{
						ResponseEndpointObject: ResponseEndpointObject{
							Host:  testkit.WarpHostPrimary,
							V4:    testkit.WarpIPv4Enroll10,
							V6:    testkit.WarpIPv6Enroll10,
							Ports: []uint16{443},
						},
					},
				}},
			},
		},
	}
	svc := &Service{
		client: client,
		store:  store,
		generateKeyPair: func(keyType string) (DeviceKeyPair, error) {
			return DeviceKeyPair{
				Type:       keyType,
				PublicKey:  "public-key-123",
				PrivateKey: testDevicePrivateKeyBase64,
			}, nil
		},
	}

	result, err := svc.Ensure(context.Background())
	if err != nil {
		t.Fatalf("expected ensure success, got %v", err)
	}
	if result.Action != ActionRegister {
		t.Fatalf("expected action %q, got %q", ActionRegister, result.Action)
	}
	if client.registerCalls != 1 {
		t.Fatalf("expected one register call, got %d", client.registerCalls)
	}
	if client.enrollCalls != 1 {
		t.Fatalf("expected one enroll call, got %d", client.enrollCalls)
	}
	if result.State.DeviceID != testAuthDeviceID {
		t.Fatalf("expected device id in result, got %q", result.State.DeviceID)
	}
	if result.State.Token != testAuthTokenEnrolled {
		t.Fatalf("expected final token in result, got %q", result.State.Token)
	}
	if result.State.Certificate.PrivateKey != testDevicePrivateKeyBase64 {
		t.Fatalf("expected private key saved, got %q", result.State.Certificate.PrivateKey)
	}
	if result.State.Certificate.ClientCertificate == "" {
		t.Fatal("expected generated client certificate")
	}
	if result.State.Certificate.PeerPublicKey != testAuthPeerPublicKey {
		t.Fatalf("expected peer public key, got %q", result.State.Certificate.PeerPublicKey)
	}
	if result.State.Certificate.ClientID != testAuthClientID {
		t.Fatalf("expected client id, got %q", result.State.Certificate.ClientID)
	}
	if result.State.Account.State != testAuthAccountStateRegister {
		t.Fatalf("expected registered state, got %q", result.State.Account.State)
	}
	if result.State.Account.AccountType != testAuthAccountTypePlus {
		t.Fatalf("expected plus account type, got %q", result.State.Account.AccountType)
	}
	if len(result.State.NodeCache) != 1 {
		t.Fatalf("expected one cached node, got %d", len(result.State.NodeCache))
	}
	if result.State.SelectedNode != result.State.NodeCache[0].ID {
		t.Fatalf("expected selected node to default to first node, got %q", result.State.SelectedNode)
	}
	if store.saved.DeviceID != testAuthDeviceID {
		t.Fatalf("expected saved device id, got %q", store.saved.DeviceID)
	}
	if store.saved.Token != testAuthTokenEnrolled {
		t.Fatalf("expected saved token, got %q", store.saved.Token)
	}
}

func TestServiceEnsureReusesStoredCredentials(t *testing.T) {
	store := &stubStateStore{
		state: storage.State{
			DeviceID: testAuthDeviceID,
			Token:    "token-existing",
			Certificate: storage.Certificate{
				PrivateKey: testDevicePrivateKeyBase64,
			},
			Account: storage.AccountStatus{
				State:       testAuthAccountStateRegister,
				AccountType: "free",
			},
			SelectedNode: testAuthSelectedNode,
			NodeCache: []storage.Node{
				{
					ID:         testAuthSelectedNode,
					Host:       testkit.WarpHostPrimary,
					EndpointV4: testkit.WarpIPv4Primary443,
					PublicKey:  "peer-old",
				},
			},
		},
	}
	client := &stubAuthClient{
		enrollResponse: Response{
			ID:    testAuthDeviceID,
			Token: "token-refreshed",
			Account: ResponseAccount{
				ID:      testAuthAccountID,
				Type:    testAuthAccountTypePlus,
				License: testAuthLicense,
			},
			Config: ResponseConfig{
				ClientID: testAuthClientID,
				Peers: []ResponsePeer{{
					PublicKey: "peer-new",
					Endpoint: ResponseEndpoint{
						ResponseEndpointObject: ResponseEndpointObject{
							Host:  testkit.WarpHostPrimary,
							V4:    testkit.WarpIPv4Enroll20,
							V6:    testkit.WarpIPv6Enroll20,
							Ports: []uint16{443, 500},
						},
					},
				}},
			},
		},
	}
	svc := &Service{
		client: client,
		store:  store,
		loadKeyPair: func(keyType, privateKey string) (DeviceKeyPair, error) {
			return DeviceKeyPair{
				Type:       keyType,
				PublicKey:  "public-key-reused",
				PrivateKey: privateKey,
			}, nil
		},
	}

	result, err := svc.Ensure(context.Background())
	if err != nil {
		t.Fatalf("expected ensure success, got %v", err)
	}
	if result.Action != ActionReuse {
		t.Fatalf("expected action %q, got %q", ActionReuse, result.Action)
	}
	if client.registerCalls != 0 {
		t.Fatalf("expected register not called, got %d", client.registerCalls)
	}
	if client.enrollCalls != 1 {
		t.Fatalf("expected one enroll call, got %d", client.enrollCalls)
	}
	if client.lastEnrollDeviceID != testAuthDeviceID {
		t.Fatalf("expected reuse device id, got %q", client.lastEnrollDeviceID)
	}
	if client.lastEnrollToken != "token-existing" {
		t.Fatalf("expected reuse token, got %q", client.lastEnrollToken)
	}
	if result.State.Token != "token-refreshed" {
		t.Fatalf("expected refreshed token, got %q", result.State.Token)
	}
	if result.State.SelectedNode != testAuthSelectedNode {
		t.Fatalf("expected selected node preserved, got %q", result.State.SelectedNode)
	}
	if len(result.State.NodeCache) != 1 || result.State.NodeCache[0].PublicKey != "peer-new" {
		t.Fatalf("expected node cache refreshed, got %+v", result.State.NodeCache)
	}
}

func TestServiceEnsureFallsBackToRegisterWhenReuseUnauthorized(t *testing.T) {
	store := &stubStateStore{
		state: storage.State{
			DeviceID: "device-old",
			Token:    "token-old",
			Certificate: storage.Certificate{
				PrivateKey: testDevicePrivateKeyBase64,
			},
		},
	}
	client := &stubAuthClient{
		enrollErr: &APIError{StatusCode: 401, Message: "unauthorized"},
		registerResponse: Response{
			ID:    testAuthReplacementDeviceID,
			Token: testAuthTokenRegister,
			Account: ResponseAccount{
				ID:   testAuthAccountID,
				Type: "free",
			},
		},
		enrollResponses: []Response{
			{
				ID:    testAuthReplacementDeviceID,
				Token: testAuthTokenEnrolled,
				Account: ResponseAccount{
					ID:      testAuthAccountID,
					Type:    testAuthAccountTypePlus,
					License: testAuthLicense,
				},
			},
		},
	}
	svc := &Service{
		client: client,
		store:  store,
		generateKeyPair: func(keyType string) (DeviceKeyPair, error) {
			return DeviceKeyPair{
				Type:       keyType,
				PublicKey:  "public-key-new",
				PrivateKey: testDevicePrivateKeyBase64,
			}, nil
		},
		loadKeyPair: func(keyType, privateKey string) (DeviceKeyPair, error) {
			return DeviceKeyPair{
				Type:       keyType,
				PublicKey:  "public-key-old",
				PrivateKey: privateKey,
			}, nil
		},
	}

	result, err := svc.Ensure(context.Background())
	if err != nil {
		t.Fatalf("expected ensure success after fallback, got %v", err)
	}
	if result.Action != ActionRegister {
		t.Fatalf("expected fallback action %q, got %q", ActionRegister, result.Action)
	}
	if client.registerCalls != 1 {
		t.Fatalf("expected register fallback, got %d", client.registerCalls)
	}
	if client.enrollCalls != 2 {
		t.Fatalf("expected one failed reuse and one enroll after register, got %d", client.enrollCalls)
	}
	if result.State.DeviceID != testAuthReplacementDeviceID {
		t.Fatalf("expected new device id, got %q", result.State.DeviceID)
	}
}

func TestServiceEnsureReturnsReuseErrorWhenRateLimited(t *testing.T) {
	store := &stubStateStore{
		state: storage.State{
			DeviceID: testAuthDeviceID,
			Token:    "token-123",
			Certificate: storage.Certificate{
				PrivateKey: testDevicePrivateKeyBase64,
			},
		},
	}
	client := &stubAuthClient{
		enrollErr: &APIError{StatusCode: 429, Message: "rate limit"},
	}
	svc := &Service{
		client: client,
		store:  store,
		loadKeyPair: func(keyType, privateKey string) (DeviceKeyPair, error) {
			return DeviceKeyPair{
				Type:       keyType,
				PublicKey:  "public-key-123",
				PrivateKey: privateKey,
			}, nil
		},
	}

	_, err := svc.Ensure(context.Background())
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	if client.registerCalls != 0 {
		t.Fatalf("expected no register fallback on rate limit, got %d", client.registerCalls)
	}
	if !errors.Is(err, client.enrollErr) {
		t.Fatalf("expected original enroll error, got %v", err)
	}
}

type stubStateStore struct {
	state   storage.State
	loadErr error
	saved   storage.State
	saveErr error
}

func (s *stubStateStore) Load() (storage.State, error) {
	if s.loadErr != nil {
		return storage.State{}, s.loadErr
	}
	return s.state, nil
}

func (s *stubStateStore) Save(state storage.State) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = state
	return nil
}

type stubAuthClient struct {
	registerResponse   Response
	registerErr        error
	enrollResponse     Response
	enrollResponses    []Response
	enrollErr          error
	registerCalls      int
	enrollCalls        int
	lastEnrollDeviceID string
	lastEnrollToken    string
}

func (s *stubAuthClient) Register(_ context.Context, _ Request) (Response, error) {
	s.registerCalls++
	if s.registerErr != nil {
		return Response{}, s.registerErr
	}
	return s.registerResponse, nil
}

func (s *stubAuthClient) Enroll(_ context.Context, deviceID, token string, _ EnrollRequest) (Response, error) {
	s.enrollCalls++
	s.lastEnrollDeviceID = deviceID
	s.lastEnrollToken = token
	if s.enrollCalls == 1 && s.enrollErr != nil {
		return Response{}, s.enrollErr
	}
	if len(s.enrollResponses) > 0 {
		if idx := s.enrollCalls - 1; idx < len(s.enrollResponses) {
			return s.enrollResponses[idx], nil
		}
	}
	return s.enrollResponse, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type transportFunc func(context.Context, TransportRequest) ([]byte, error)

func (f transportFunc) Do(ctx context.Context, req TransportRequest) ([]byte, error) {
	return f(ctx, req)
}

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
			return []byte(`{"id":"` + testAuthRegisterDeviceID + `","token":"` + testAuthRegisterToken + `"}`), nil
		}
		if req.Method == http.MethodPatch {
			if req.Path != "/reg/"+testAuthRegisterDeviceID {
				t.Fatalf("expected enroll path, got %q", req.Path)
			}
			if req.BearerToken != testAuthRegisterToken {
				t.Fatalf("expected bearer token, got %q", req.BearerToken)
			}
			return []byte(`{"id":"` + testAuthRegisterDeviceID + `","token":"` + testAuthEnrollToken + `"}`), nil
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
	if registered.ID != testAuthRegisterDeviceID || registered.Token != testAuthRegisterToken {
		t.Fatalf("unexpected register response: %+v", registered)
	}

	enrolled, err := client.Enroll(context.Background(), testAuthRegisterDeviceID, testAuthRegisterToken, EnrollRequest{Key: "pub"})
	if err != nil {
		t.Fatalf("expected enroll success, got %v", err)
	}
	if enrolled.Token != testAuthEnrollToken {
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
	if _, err := LoadDeviceKeyPair(DefaultDeviceKeyType, base64.StdEncoding.EncodeToString([]byte("not-a-key"))); err == nil || !strings.Contains(err.Error(), "parse device private key") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestHTTPTransportBuildsRequestsAndParsesErrors(t *testing.T) {
	transport, err := NewHTTPTransport(testAuthTransportBaseURL, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != testAuthTransportRequestURL {
			t.Fatalf("unexpected request url: %s", req.URL.String())
		}
		if got := req.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("expected authorization header, got %q", got)
		}
		if req.Header.Get("CF-Client-Version") == "" {
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

	previous := storage.State{SelectedNode: testAuthSelectedNode, NodeCache: []storage.Node{{ID: testAuthSelectedNode, PublicKey: "old"}}, Interface: storage.InterfaceAddresses{V4: testAuthIPv4Addr}, Services: storage.Services{HTTPProxy: "http://old"}}
	final := Response{ID: testAuthRegisterDeviceID, Token: testAuthEnrollToken, Account: ResponseAccount{Type: testAuthAccountTypePlus, License: "lic"}, Config: ResponseConfig{ClientID: "cid", Interface: ResponseConfigInterface{Addresses: storage.InterfaceAddresses{V6: testkit.WarpIPv6Primary443}}, Services: ResponseConfigServices{HTTPProxy: "http://new"}, Peers: []ResponsePeer{{PublicKey: "pk2", Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Host: testkit.WarpHostPrimary, V4: testkit.TestIPv4Echo, Ports: []uint16{500}}}}, {PublicKey: "pk1", Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V6: testkit.WarpIPv6Primary443}}}}}}
	state, err := buildState(previous, pair.PrivateKey, "fallback-token", final)
	if err != nil {
		t.Fatalf("expected buildState success, got %v", err)
	}
	if state.Token != testAuthEnrollToken || state.Certificate.PeerPublicKey == "" || len(state.NodeCache) != 2 {
		t.Fatalf("unexpected built state: %+v", state)
	}
	if state.SelectedNode != testAuthSelectedNode {
		t.Fatalf("expected selected node preserved, got %q", state.SelectedNode)
	}
	if got := normalizePeerEndpoint(testkit.TestIPv6Doc, 443); !strings.HasPrefix(got, "[") {
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
	if err := endpoint.UnmarshalJSON([]byte(`{"host":"api.example","v4":"` + testAuthIPv4Addr + `","ports":[443]}`)); err != nil {
		t.Fatalf("expected object endpoint success, got %v", err)
	}
	if endpoint.PreferredAddress() != "api.example" {
		t.Fatalf("unexpected preferred object address: %q", endpoint.PreferredAddress())
	}
	if err := endpoint.UnmarshalJSON([]byte(`123`)); err == nil {
		t.Fatal("expected unsupported endpoint payload error")
	}
	var iface ResponseConfigInterface
	if err := iface.UnmarshalJSON([]byte(`{"v4":"` + testAuthIPv4Addr + `","v6":"` + testAuthIPv6Addr + `"}`)); err != nil {
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
		t.Fatalf(errUnexpectedAPIErrorString, got)
	}
	if got := (&APIError{StatusCode: 400, Message: "bad"}).Error(); !strings.Contains(got, "message=bad") {
		t.Fatalf(errUnexpectedAPIErrorString, got)
	}
	if got := (&APIError{StatusCode: 400}).Error(); !strings.Contains(got, "status=400") {
		t.Fatalf(errUnexpectedAPIErrorString, got)
	}
	if ((*APIError)(nil)).Error() == "" {
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
	if extractAPIError(500, []byte(`{}`)) == nil {
		t.Fatal("expected fallback api error on empty error envelope")
	}

	endpoint := ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: testAuthIPv4Addr, V6: testAuthIPv6Addr, Addr: "raw"}}
	if got := endpoint.PreferredAddress(); got != testAuthIPv4Addr {
		t.Fatalf("unexpected preferred address: %q", got)
	}
	endpoint = ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V6: testAuthIPv6Addr, Addr: "raw"}}
	if got := endpoint.PreferredAddress(); got != testAuthIPv6Addr {
		t.Fatalf("unexpected preferred ipv6 address: %q", got)
	}
	endpoint = ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Addr: "raw"}}
	if got := endpoint.PreferredAddress(); got != "raw" {
		t.Fatalf("unexpected preferred raw address: %q", got)
	}

	if got := buildNodeID(ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Host: testAuthHost}}}); got != testAuthHost {
		t.Fatalf("unexpected node id from host: %q", got)
	}
	if buildNodeID(ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: testAuthIPv4Addr, Ports: []uint16{443}}}}) == "" {
		t.Fatal("expected node id from ipv4 endpoint")
	}
	if got := comparePeer(
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Host: testAuthHost, V4: testAuthIPv4Addr, Ports: []uint16{443}}}},
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: testAuthIPv4AltAddr}}},
	); got <= 0 {
		t.Fatalf("expected richer peer to compare greater, got %d", got)
	}
	if got := comparePeer(
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: testAuthIPv4Addr}}},
		ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: testAuthIPv4AltAddr}}},
	); got >= 0 {
		t.Fatalf("expected lexical compare ordering, got %d", got)
	}
}

func TestAdditionalAuthModelBranches(t *testing.T) {
	if got := buildNodeCache([]ResponsePeer{{}}); len(got) != 0 {
		t.Fatalf("expected empty node cache for empty peer id, got %+v", got)
	}
	if buildNodeID(ResponsePeer{Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V6: testkit.TestIPv6Doc}}}) == "" {
		t.Fatal("expected node id from ipv6 endpoint")
	}
	if got := selectPeer([]ResponsePeer{
		{PublicKey: "a", Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{V4: testAuthIPv4Addr}}},
		{PublicKey: "b", Endpoint: ResponseEndpoint{ResponseEndpointObject: ResponseEndpointObject{Host: testAuthHost, V4: testAuthIPv4AltAddr, Ports: []uint16{443}}}},
	}); got.PublicKey != "b" {
		t.Fatalf("expected richer peer selected, got %+v", got)
	}
	if got := firstNonEmpty("", "", ""); got != "" {
		t.Fatalf("expected empty firstNonEmpty result, got %q", got)
	}
	if got := selectServices(storage.Services{}, storage.Services{}); got.HTTPProxy != "" {
		t.Fatalf("expected empty selected services, got %+v", got)
	}
	if got := summarizeAccountStatus(Response{}, ""); got.State != "empty" {
		t.Fatalf("expected empty summarized account state, got %+v", got)
	}
}

func ioNopCloser(body string) *readCloser { return &readCloser{Reader: strings.NewReader(body)} }

type readCloser struct{ *strings.Reader }

func (r *readCloser) Close() error { return nil }
