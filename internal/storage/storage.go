package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	CurrentVersion    = "1"
	stateDirName      = "amz"
	stateFileName     = "state.json"
	fallbackConfigDir = ".config"
)

type State struct {
	Version      string             `json:"version"`
	DeviceID     string             `json:"device_id,omitempty"`
	Token        string             `json:"token,omitempty"`
	Certificate  Certificate        `json:"certificate,omitempty"`
	Account      AccountStatus      `json:"account,omitempty"`
	Interface    InterfaceAddresses `json:"interface,omitempty"`
	Services     Services           `json:"services,omitempty"`
	SelectedNode string             `json:"selected_node,omitempty"`
	NodeCache    []Node             `json:"node_cache,omitempty"`
}

type Certificate struct {
	PrivateKey        string `json:"private_key,omitempty"`
	ClientCertificate string `json:"client_certificate,omitempty"`
	PeerPublicKey     string `json:"peer_public_key,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
}

type AccountStatus struct {
	State       string `json:"state,omitempty"`
	AccountType string `json:"account_type,omitempty"`
}

type InterfaceAddresses struct {
	V4 string `json:"v4,omitempty"`
	V6 string `json:"v6,omitempty"`
}

type Services struct {
	HTTPProxy string `json:"http_proxy,omitempty"`
}

type Node struct {
	ID         string   `json:"id"`
	Host       string   `json:"host,omitempty"`
	EndpointV4 string   `json:"endpoint_v4,omitempty"`
	EndpointV6 string   `json:"endpoint_v6,omitempty"`
	PublicKey  string   `json:"public_key,omitempty"`
	Ports      []uint16 `json:"ports,omitempty"`
}

func DefaultState() State {
	return State{
		Version:   CurrentVersion,
		NodeCache: []Node{},
	}
}

func (s State) normalized() State {
	if s.Version == "" {
		s.Version = CurrentVersion
	}
	if s.NodeCache == nil {
		s.NodeCache = []Node{}
	}
	return s
}

func DefaultPath() (string, error) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		userConfigDir, err := os.UserConfigDir()
		if err != nil {
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return "", fmt.Errorf("resolve home dir: %w", err)
			}
			configHome = filepath.Join(home, fallbackConfigDir)
		} else {
			configHome = userConfigDir
		}
	}
	return filepath.Join(configHome, stateDirName, stateFileName), nil
}

func Write(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(state.normalized(), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func Read(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("read state: %w", err)
	}
	state := DefaultState()
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("unmarshal state: %w", err)
	}
	return state.normalized(), nil
}

type FileStore struct {
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) Load() (State, error) {
	if s == nil {
		return State{}, fmt.Errorf("file store is required")
	}
	return Read(s.path)
}

func (s *FileStore) Save(state State) error {
	if s == nil {
		return fmt.Errorf("file store is required")
	}
	return Write(s.path, state)
}
