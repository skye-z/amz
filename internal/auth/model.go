package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/skye-z/amz/internal/storage"
)

const (
	DefaultDeviceModel      = "amz"
	DefaultDeviceLocale     = "en_US"
	DefaultDeviceKeyType    = "secp256r1"
	DefaultDeviceTunnelType = "masque"
)

type DeviceIdentity struct {
	Model      string
	Locale     string
	KeyType    string
	TunnelType string
}

func DefaultDeviceIdentity() DeviceIdentity {
	return DeviceIdentity{
		Model:      DefaultDeviceModel,
		Locale:     DefaultDeviceLocale,
		KeyType:    DefaultDeviceKeyType,
		TunnelType: DefaultDeviceTunnelType,
	}
}

type Request struct {
	Key         string `json:"key"`
	InstallID   string `json:"install_id"`
	FcmToken    string `json:"fcm_token"`
	TOS         string `json:"tos"`
	Type        string `json:"type,omitempty"`
	Locale      string `json:"locale"`
	WarpEnabled bool   `json:"warp_enabled,omitempty"`
	Model       string `json:"model,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	TunType     string `json:"tunnel_type,omitempty"`
}

type Response struct {
	Success  *bool           `json:"success,omitempty"`
	Messages []string        `json:"messages,omitempty"`
	Errors   []ResponseError `json:"errors,omitempty"`
	ID       string          `json:"id"`
	Token    string          `json:"token"`
	Account  ResponseAccount `json:"account"`
	Config   ResponseConfig  `json:"config"`
}

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ResponseAccount struct {
	ID      string `json:"id"`
	Type    string `json:"account_type"`
	License string `json:"license"`
}

type ResponseConfig struct {
	ClientID  string                  `json:"client_id"`
	Peers     []ResponsePeer          `json:"peers,omitempty"`
	Interface ResponseConfigInterface `json:"interface,omitempty"`
	Services  ResponseConfigServices  `json:"services,omitempty"`
}

type ResponseConfigInterface struct {
	Addresses storage.InterfaceAddresses `json:"addresses,omitempty"`
}

func (i *ResponseConfigInterface) UnmarshalJSON(data []byte) error {
	type alias ResponseConfigInterface
	var nested alias
	if err := json.Unmarshal(data, &nested); err == nil && (nested.Addresses.V4 != "" || nested.Addresses.V6 != "") {
		*i = ResponseConfigInterface(nested)
		return nil
	}
	var flat storage.InterfaceAddresses
	if err := json.Unmarshal(data, &flat); err == nil {
		i.Addresses = flat
		return nil
	}
	return nil
}

type ResponseConfigServices struct {
	HTTPProxy string `json:"http_proxy,omitempty"`
}

type ResponsePeer struct {
	PublicKey string           `json:"public_key"`
	Endpoint  ResponseEndpoint `json:"endpoint"`
}

type ResponseEndpointObject struct {
	Host  string   `json:"host"`
	V4    string   `json:"v4"`
	V6    string   `json:"v6"`
	Addr  string   `json:"addr"`
	Ports []uint16 `json:"ports,omitempty"`
}

type ResponseEndpoint struct {
	Raw string
	ResponseEndpointObject
}

func (e *ResponseEndpoint) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*e = ResponseEndpoint{}
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		e.Raw = text
		return nil
	}
	var object ResponseEndpointObject
	if err := json.Unmarshal(data, &object); err == nil {
		e.Raw = string(data)
		e.ResponseEndpointObject = object
		return nil
	}
	return fmt.Errorf("unmarshal response endpoint: unsupported payload %s", string(data))
}

func (e ResponseEndpoint) PreferredAddress() string {
	switch {
	case strings.TrimSpace(e.Host) != "":
		return strings.TrimSpace(e.Host)
	case strings.TrimSpace(e.V4) != "":
		return strings.TrimSpace(e.V4)
	case strings.TrimSpace(e.V6) != "":
		return strings.TrimSpace(e.V6)
	case strings.TrimSpace(e.Addr) != "":
		return strings.TrimSpace(e.Addr)
	default:
		return strings.TrimSpace(e.Raw)
	}
}

type EnrollRequest struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
}

func BuildRegisterRequest(pair DeviceKeyPair, device DeviceIdentity) Request {
	device = device.withDefaults()
	return Request{
		Key:         pair.PublicKey,
		InstallID:   generateInstallID(),
		FcmToken:    "",
		TOS:         time.Now().UTC().Format(time.RFC3339Nano),
		Type:        "Android",
		Locale:      device.Locale,
		WarpEnabled: true,
		Model:       device.Model,
		KeyType:     device.KeyType,
		TunType:     device.TunnelType,
	}
}

func BuildEnrollRequest(pair DeviceKeyPair, device DeviceIdentity) EnrollRequest {
	device = device.withDefaults()
	return EnrollRequest{
		Key:     pair.PublicKey,
		KeyType: device.KeyType,
		TunType: device.TunnelType,
	}
}

func GenerateClientCertificate(privateKey string) (string, error) {
	priv, err := parseECDSAPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now().UTC().Add(-1 * time.Minute),
		NotAfter:     time.Now().UTC().Add(24 * time.Hour),
	}, &x509.Certificate{}, &priv.PublicKey, priv)
	if err != nil {
		return "", fmt.Errorf("generate client certificate: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func buildState(previous storage.State, privateKey, fallbackToken string, final Response) (storage.State, error) {
	clientCertificate, err := GenerateClientCertificate(privateKey)
	if err != nil {
		return storage.State{}, fmt.Errorf("generate client certificate from device key: %w", err)
	}

	state := storage.DefaultState()
	state.DeviceID = firstNonEmpty(final.ID, previous.DeviceID)
	state.Token = firstNonEmpty(final.Token, fallbackToken)
	state.Certificate = storage.Certificate{
		PrivateKey:        privateKey,
		ClientCertificate: clientCertificate,
		ClientID:          strings.TrimSpace(final.Config.ClientID),
	}
	state.Account = summarizeAccountStatus(final, state.Token)
	state.Interface = selectInterface(final.Config.Interface.Addresses, previous.Interface)
	state.Services = selectServices(storage.Services{HTTPProxy: final.Config.Services.HTTPProxy}, previous.Services)
	state.SelectedNode = previous.SelectedNode
	state.NodeCache = cloneNodes(previous.NodeCache)

	if len(final.Config.Peers) > 0 {
		state.NodeCache = buildNodeCache(final.Config.Peers)
		if peer := selectPeer(final.Config.Peers); strings.TrimSpace(peer.PublicKey) != "" {
			state.Certificate.PeerPublicKey = strings.TrimSpace(peer.PublicKey)
		}
	}
	if state.SelectedNode == "" && len(state.NodeCache) > 0 {
		state.SelectedNode = state.NodeCache[0].ID
	}
	return state, nil
}

func summarizeAccountStatus(final Response, token string) storage.AccountStatus {
	accountType := strings.TrimSpace(final.Account.Type)
	if accountType == "" {
		if strings.TrimSpace(final.Account.License) != "" {
			accountType = "plus"
		} else {
			accountType = "unknown"
		}
	}
	state := "empty"
	if strings.TrimSpace(final.ID) != "" || strings.TrimSpace(token) != "" {
		state = "registered"
	}
	return storage.AccountStatus{
		State:       state,
		AccountType: accountType,
	}
}

func buildNodeCache(peers []ResponsePeer) []storage.Node {
	nodes := make([]storage.Node, 0, len(peers))
	for _, peer := range peers {
		nodeID := buildNodeID(peer)
		if nodeID == "" {
			continue
		}
		nodes = append(nodes, storage.Node{
			ID:         nodeID,
			Host:       strings.TrimSpace(peer.Endpoint.Host),
			EndpointV4: normalizePeerEndpoint(peer.Endpoint.V4, selectPeerPort(peer.Endpoint.Ports)),
			EndpointV6: normalizePeerEndpoint(peer.Endpoint.V6, selectPeerPort(peer.Endpoint.Ports)),
			PublicKey:  strings.TrimSpace(peer.PublicKey),
			Ports:      append([]uint16(nil), peer.Endpoint.Ports...),
		})
	}
	return nodes
}

func cloneNodes(nodes []storage.Node) []storage.Node {
	cloned := make([]storage.Node, 0, len(nodes))
	for _, node := range nodes {
		cloned = append(cloned, storage.Node{
			ID:         node.ID,
			Host:       node.Host,
			EndpointV4: node.EndpointV4,
			EndpointV6: node.EndpointV6,
			PublicKey:  node.PublicKey,
			Ports:      append([]uint16(nil), node.Ports...),
		})
	}
	return cloned
}

func buildNodeID(peer ResponsePeer) string {
	if key := strings.TrimSpace(peer.PublicKey); key != "" {
		return key
	}
	if host := strings.TrimSpace(peer.Endpoint.Host); host != "" {
		return host
	}
	if endpoint := normalizePeerEndpoint(peer.Endpoint.V4, selectPeerPort(peer.Endpoint.Ports)); endpoint != "" {
		return endpoint
	}
	return normalizePeerEndpoint(peer.Endpoint.V6, selectPeerPort(peer.Endpoint.Ports))
}

func selectPeer(peers []ResponsePeer) ResponsePeer {
	best := peers[0]
	for _, candidate := range peers[1:] {
		if comparePeer(candidate, best) > 0 {
			best = candidate
		}
	}
	return best
}

func comparePeer(left, right ResponsePeer) int {
	leftScore := scorePeer(left)
	rightScore := scorePeer(right)
	if leftScore != rightScore {
		if leftScore > rightScore {
			return 1
		}
		return -1
	}
	leftAddr := normalizePeerEndpoint(left.Endpoint.V4, selectPeerPort(left.Endpoint.Ports))
	rightAddr := normalizePeerEndpoint(right.Endpoint.V4, selectPeerPort(right.Endpoint.Ports))
	if leftAddr > rightAddr {
		return 1
	}
	if leftAddr < rightAddr {
		return -1
	}
	return 0
}

func scorePeer(peer ResponsePeer) int {
	score := 0
	if strings.TrimSpace(peer.Endpoint.Host) != "" {
		score += 4
	}
	if len(peer.Endpoint.Ports) > 0 {
		score += 2
	}
	if strings.TrimSpace(peer.Endpoint.V4) != "" {
		score++
	}
	if strings.TrimSpace(peer.Endpoint.V6) != "" {
		score++
	}
	return score
}

func selectPeerPort(ports []uint16) int {
	for _, p := range ports {
		if p > 0 {
			return int(p)
		}
	}
	return 443
}

func normalizePeerEndpoint(raw string, defaultPort int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		if port == "" || port == "0" {
			return net.JoinHostPort(host, strconv.Itoa(defaultPort))
		}
		return raw
	}
	if strings.Contains(raw, ":") && strings.Count(raw, ":") > 1 && !strings.HasPrefix(raw, "[") {
		return net.JoinHostPort(raw, strconv.Itoa(defaultPort))
	}
	return net.JoinHostPort(raw, strconv.Itoa(defaultPort))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func selectInterface(values ...storage.InterfaceAddresses) storage.InterfaceAddresses {
	for _, value := range values {
		if strings.TrimSpace(value.V4) != "" || strings.TrimSpace(value.V6) != "" {
			return storage.InterfaceAddresses{
				V4: strings.TrimSpace(value.V4),
				V6: strings.TrimSpace(value.V6),
			}
		}
	}
	return storage.InterfaceAddresses{}
}

func selectServices(values ...storage.Services) storage.Services {
	for _, value := range values {
		if strings.TrimSpace(value.HTTPProxy) != "" {
			return storage.Services{HTTPProxy: strings.TrimSpace(value.HTTPProxy)}
		}
	}
	return storage.Services{}
}

func generateInstallID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("install-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

func parseECDSAPrivateKey(encoded string) (*ecdsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

func (d DeviceIdentity) withDefaults() DeviceIdentity {
	defaults := DefaultDeviceIdentity()
	if strings.TrimSpace(d.Model) == "" {
		d.Model = defaults.Model
	}
	if strings.TrimSpace(d.Locale) == "" {
		d.Locale = defaults.Locale
	}
	if strings.TrimSpace(d.KeyType) == "" {
		d.KeyType = defaults.KeyType
	}
	if strings.TrimSpace(d.TunnelType) == "" {
		d.TunnelType = defaults.TunnelType
	}
	return d
}
