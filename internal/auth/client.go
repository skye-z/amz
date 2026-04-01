package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var ErrTransportRequired = errors.New("transport is required")

type TransportRequest struct {
	Method      string
	Path        string
	Body        []byte
	BearerToken string
}

type Doer interface {
	Do(ctx context.Context, req TransportRequest) ([]byte, error)
}

type Client struct {
	transport Doer
}

func NewClient(transport Doer) (*Client, error) {
	if transport == nil {
		return nil, ErrTransportRequired
	}
	return &Client{transport: transport}, nil
}

func (c *Client) Register(ctx context.Context, req Request) (Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("marshal register request: %w", err)
	}
	data, err := c.transport.Do(ctx, TransportRequest{
		Method: http.MethodPost,
		Path:   "/reg",
		Body:   body,
	})
	if err != nil {
		return Response{}, fmt.Errorf("do register request: %w", err)
	}
	return ParseResponse(data)
}

func (c *Client) Enroll(ctx context.Context, deviceID, token string, req EnrollRequest) (Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("marshal enroll request: %w", err)
	}
	data, err := c.transport.Do(ctx, TransportRequest{
		Method:      http.MethodPatch,
		Path:        "/reg/" + deviceID,
		Body:        body,
		BearerToken: token,
	})
	if err != nil {
		return Response{}, fmt.Errorf("do enroll request: %w", err)
	}
	return ParseResponse(data)
}
