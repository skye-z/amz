package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/skye-z/amz/internal/storage"
)

var (
	ErrClientRequired        = errors.New("auth client is required")
	ErrStateStoreRequired    = errors.New("state store is required")
	ErrIncompleteStoredState = errors.New("stored state is incomplete")
)

const (
	ActionRegister = "register"
	ActionReuse    = "reuse"
)

type AuthClient interface {
	Register(ctx context.Context, req Request) (Response, error)
	Enroll(ctx context.Context, deviceID, token string, req EnrollRequest) (Response, error)
}

type StateStore interface {
	Load() (storage.State, error)
	Save(state storage.State) error
}

type Result struct {
	Action string
	State  storage.State
}

type Service struct {
	client          AuthClient
	store           StateStore
	generateKeyPair func(keyType string) (DeviceKeyPair, error)
	loadKeyPair     func(keyType, privateKey string) (DeviceKeyPair, error)
}

func NewService(client AuthClient, store StateStore) (*Service, error) {
	if client == nil {
		return nil, ErrClientRequired
	}
	if store == nil {
		return nil, ErrStateStoreRequired
	}
	return &Service{
		client:          client,
		store:           store,
		generateKeyPair: GenerateDeviceKeyPair,
		loadKeyPair:     LoadDeviceKeyPair,
	}, nil
}

func NewDefaultService(path string) (*Service, error) {
	if strings.TrimSpace(path) == "" {
		defaultPath, err := storage.DefaultPath()
		if err != nil {
			return nil, err
		}
		path = defaultPath
	}
	transport, err := NewDefaultHTTPTransport()
	if err != nil {
		return nil, err
	}
	client, err := NewClient(transport)
	if err != nil {
		return nil, err
	}
	return NewService(client, storage.NewFileStore(path))
}

func (s *Service) Ensure(ctx context.Context) (Result, error) {
	return s.EnsureWithDevice(ctx, DefaultDeviceIdentity())
}

func (s *Service) EnsureWithDevice(ctx context.Context, device DeviceIdentity) (Result, error) {
	if s == nil || s.client == nil {
		return Result{}, ErrClientRequired
	}
	if s.store == nil {
		return Result{}, ErrStateStoreRequired
	}
	if s.generateKeyPair == nil {
		s.generateKeyPair = GenerateDeviceKeyPair
	}
	if s.loadKeyPair == nil {
		s.loadKeyPair = LoadDeviceKeyPair
	}
	device = device.withDefaults()

	current, err := s.store.Load()
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		current = storage.DefaultState()
	default:
		return Result{}, fmt.Errorf("load auth state: %w", err)
	}

	if isReusable(current) {
		result, reuseErr := s.reuse(ctx, current, device)
		if reuseErr == nil {
			return result, nil
		}
		if !shouldRegisterFallback(reuseErr) {
			return Result{}, reuseErr
		}
	}

	return s.register(ctx, current, device)
}

func (s *Service) reuse(ctx context.Context, current storage.State, device DeviceIdentity) (Result, error) {
	if !isReusable(current) {
		return Result{}, ErrIncompleteStoredState
	}
	pair, err := s.loadKeyPair(device.KeyType, current.Certificate.PrivateKey)
	if err != nil {
		return Result{}, fmt.Errorf("reuse device credentials: %w", err)
	}
	final, err := s.client.Enroll(ctx, current.DeviceID, current.Token, BuildEnrollRequest(pair, device))
	if err != nil {
		return Result{}, fmt.Errorf("reuse device credentials: %w", err)
	}
	state, err := buildState(current, pair.PrivateKey, current.Token, final)
	if err != nil {
		return Result{}, fmt.Errorf("reuse device credentials: %w", err)
	}
	if err := s.store.Save(state); err != nil {
		return Result{}, fmt.Errorf("save auth state: %w", err)
	}
	return Result{
		Action: ActionReuse,
		State:  state,
	}, nil
}

func (s *Service) register(ctx context.Context, current storage.State, device DeviceIdentity) (Result, error) {
	pair, err := s.generateKeyPair(device.KeyType)
	if err != nil {
		return Result{}, fmt.Errorf("generate device key pair: %w", err)
	}
	registered, err := s.client.Register(ctx, BuildRegisterRequest(pair, device))
	if err != nil {
		return Result{}, fmt.Errorf("register account: %w", err)
	}
	final, err := s.client.Enroll(ctx, registered.ID, registered.Token, BuildEnrollRequest(pair, device))
	if err != nil {
		return Result{}, fmt.Errorf("enroll device key: %w", err)
	}
	if strings.TrimSpace(final.ID) == "" {
		final.ID = registered.ID
	}
	if strings.TrimSpace(final.Account.ID) == "" {
		final.Account.ID = registered.Account.ID
	}
	state, err := buildState(current, pair.PrivateKey, registered.Token, final)
	if err != nil {
		return Result{}, err
	}
	if err := s.store.Save(state); err != nil {
		return Result{}, fmt.Errorf("save auth state: %w", err)
	}
	return Result{
		Action: ActionRegister,
		State:  state,
	}, nil
}

func isReusable(state storage.State) bool {
	return strings.TrimSpace(state.DeviceID) != "" &&
		strings.TrimSpace(state.Token) != "" &&
		strings.TrimSpace(state.Certificate.PrivateKey) != ""
}

func shouldRegisterFallback(err error) bool {
	if errors.Is(err, ErrIncompleteStoredState) || errors.Is(err, ErrUnsupportedDeviceKeyType) {
		return true
	}
	switch ClassifyAPIError(err) {
	case APIErrorCategoryUnauthorized, APIErrorCategoryInvalidRequest:
		return true
	default:
		return false
	}
}
