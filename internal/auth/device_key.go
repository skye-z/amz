package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

var ErrUnsupportedDeviceKeyType = errors.New("unsupported device key type")

type DeviceKeyPair struct {
	Type       string
	PublicKey  string
	PrivateKey string
}

func GenerateDeviceKeyPair(keyType string) (DeviceKeyPair, error) {
	if keyType != "secp256r1" {
		return DeviceKeyPair{}, fmt.Errorf("device key type %q: %w", keyType, ErrUnsupportedDeviceKeyType)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return DeviceKeyPair{}, fmt.Errorf("generate device key pair: %w", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return DeviceKeyPair{}, fmt.Errorf("marshal public key: %w", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return DeviceKeyPair{}, fmt.Errorf("marshal private key: %w", err)
	}

	return DeviceKeyPair{
		Type:       keyType,
		PublicKey:  base64.StdEncoding.EncodeToString(publicKeyDER),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKeyDER),
	}, nil
}

func LoadDeviceKeyPair(keyType, privateKey string) (DeviceKeyPair, error) {
	if keyType != "secp256r1" {
		return DeviceKeyPair{}, fmt.Errorf("device key type %q: %w", keyType, ErrUnsupportedDeviceKeyType)
	}
	rawPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return DeviceKeyPair{}, fmt.Errorf("decode device private key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(rawPrivateKey)
	if err != nil {
		return DeviceKeyPair{}, fmt.Errorf("parse device private key: %w", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return DeviceKeyPair{}, fmt.Errorf("marshal device public key: %w", err)
	}
	return DeviceKeyPair{
		Type:       keyType,
		PublicKey:  base64.StdEncoding.EncodeToString(publicKeyDER),
		PrivateKey: privateKey,
	}, nil
}
