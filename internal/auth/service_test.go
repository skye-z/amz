package auth

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/skye-z/amz/internal/storage"
	"github.com/skye-z/amz/internal/testkit"
)

func TestServiceEnsureRegistersWhenStateMissing(t *testing.T) {
	store := &stubStateStore{loadErr: os.ErrNotExist}
	client := &stubAuthClient{
		registerResponse: Response{
			ID:    "device-123",
			Token: "token-register",
			Account: ResponseAccount{
				ID:   "account-123",
				Type: "free",
			},
		},
		enrollResponse: Response{
			ID:    "device-123",
			Token: "token-enrolled",
			Account: ResponseAccount{
				ID:      "account-123",
				Type:    "plus",
				License: "license-123",
			},
			Config: ResponseConfig{
				ClientID: "client-id-123",
				Peers: []ResponsePeer{{
					PublicKey: "peer-public-key-123",
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
	if result.State.DeviceID != "device-123" {
		t.Fatalf("expected device id in result, got %q", result.State.DeviceID)
	}
	if result.State.Token != "token-enrolled" {
		t.Fatalf("expected final token in result, got %q", result.State.Token)
	}
	if result.State.Certificate.PrivateKey != testDevicePrivateKeyBase64 {
		t.Fatalf("expected private key saved, got %q", result.State.Certificate.PrivateKey)
	}
	if result.State.Certificate.ClientCertificate == "" {
		t.Fatal("expected generated client certificate")
	}
	if result.State.Certificate.PeerPublicKey != "peer-public-key-123" {
		t.Fatalf("expected peer public key, got %q", result.State.Certificate.PeerPublicKey)
	}
	if result.State.Certificate.ClientID != "client-id-123" {
		t.Fatalf("expected client id, got %q", result.State.Certificate.ClientID)
	}
	if result.State.Account.State != "registered" {
		t.Fatalf("expected registered state, got %q", result.State.Account.State)
	}
	if result.State.Account.AccountType != "plus" {
		t.Fatalf("expected plus account type, got %q", result.State.Account.AccountType)
	}
	if len(result.State.NodeCache) != 1 {
		t.Fatalf("expected one cached node, got %d", len(result.State.NodeCache))
	}
	if result.State.SelectedNode != result.State.NodeCache[0].ID {
		t.Fatalf("expected selected node to default to first node, got %q", result.State.SelectedNode)
	}
	if store.saved.DeviceID != "device-123" {
		t.Fatalf("expected saved device id, got %q", store.saved.DeviceID)
	}
	if store.saved.Token != "token-enrolled" {
		t.Fatalf("expected saved token, got %q", store.saved.Token)
	}
}

func TestServiceEnsureReusesStoredCredentials(t *testing.T) {
	store := &stubStateStore{
		state: storage.State{
			DeviceID: "device-123",
			Token:    "token-existing",
			Certificate: storage.Certificate{
				PrivateKey: testDevicePrivateKeyBase64,
			},
			Account: storage.AccountStatus{
				State:       "registered",
				AccountType: "free",
			},
			SelectedNode: "node-keep",
			NodeCache: []storage.Node{
				{
					ID:         "node-keep",
					Host:       testkit.WarpHostPrimary,
					EndpointV4: testkit.WarpIPv4Primary443,
					PublicKey:  "peer-old",
				},
			},
		},
	}
	client := &stubAuthClient{
		enrollResponse: Response{
			ID:    "device-123",
			Token: "token-refreshed",
			Account: ResponseAccount{
				ID:      "account-123",
				Type:    "plus",
				License: "license-123",
			},
			Config: ResponseConfig{
				ClientID: "client-id-123",
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
	if client.lastEnrollDeviceID != "device-123" {
		t.Fatalf("expected reuse device id, got %q", client.lastEnrollDeviceID)
	}
	if client.lastEnrollToken != "token-existing" {
		t.Fatalf("expected reuse token, got %q", client.lastEnrollToken)
	}
	if result.State.Token != "token-refreshed" {
		t.Fatalf("expected refreshed token, got %q", result.State.Token)
	}
	if result.State.SelectedNode != "node-keep" {
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
			ID:    "device-new",
			Token: "token-register",
			Account: ResponseAccount{
				ID:   "account-123",
				Type: "free",
			},
		},
		enrollResponses: []Response{
			{
				ID:    "device-new",
				Token: "token-enrolled",
				Account: ResponseAccount{
					ID:      "account-123",
					Type:    "plus",
					License: "license-123",
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
	if result.State.DeviceID != "device-new" {
		t.Fatalf("expected new device id, got %q", result.State.DeviceID)
	}
}

func TestServiceEnsureReturnsReuseErrorWhenRateLimited(t *testing.T) {
	store := &stubStateStore{
		state: storage.State{
			DeviceID: "device-123",
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
		idx := s.enrollCalls - 1
		if idx < len(s.enrollResponses) {
			return s.enrollResponses[idx], nil
		}
	}
	return s.enrollResponse, nil
}

const testDevicePrivateKeyBase64 = "MHcCAQEEIP2wC9ZwTe74MkRUYw35vj0IadB1iKsFcfoTmyaKOAqvoAoGCCqGSM49AwEHoUQDQgAEiKxuxMxDPZWS9Vyuk3F7S3w7Dnk3a1JpN96CB2A+qsSVqS+8CA0nVddOZXS6jttuPAHyBs+K6TfGsDz3jACzmw=="
