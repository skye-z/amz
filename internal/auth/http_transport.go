package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var ErrHTTPDoerRequired = errors.New("http doer is required")

const defaultRegisterBaseURL = "https://api.cloudflareclient.com"
const defaultRegisterAPIVersion = "v0a4471"

var defaultRegisterHeaders = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}

type APIError struct {
	StatusCode int
	Code       int
	Message    string
}

type APIErrorCategory string

const (
	APIErrorCategoryUnknown        APIErrorCategory = "unknown"
	APIErrorCategoryUnauthorized   APIErrorCategory = "unauthorized"
	APIErrorCategoryInvalidRequest APIErrorCategory = "invalid_request"
	APIErrorCategoryRateLimited    APIErrorCategory = "rate_limited"
	APIErrorCategoryServer         APIErrorCategory = "server"
)

func (e *APIError) Error() string {
	if e == nil {
		return "register api error"
	}
	if e.Code != 0 && strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("register api error: status=%d code=%d message=%s", e.StatusCode, e.Code, e.Message)
	}
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("register api error: status=%d message=%s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("register api error: status=%d", e.StatusCode)
}

func (e *APIError) Category() APIErrorCategory {
	if e == nil {
		return APIErrorCategoryUnknown
	}
	message := strings.ToLower(strings.TrimSpace(e.Message))
	switch {
	case e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden:
		return APIErrorCategoryUnauthorized
	case e.StatusCode == http.StatusTooManyRequests || e.Code == 1015 || strings.Contains(message, "rate limit") || strings.Contains(message, "too many requests"):
		return APIErrorCategoryRateLimited
	case e.StatusCode >= http.StatusInternalServerError:
		return APIErrorCategoryServer
	case e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusUnprocessableEntity || e.StatusCode == http.StatusNotFound || e.StatusCode == http.StatusConflict:
		return APIErrorCategoryInvalidRequest
	case strings.Contains(message, "unauthorized"), strings.Contains(message, "forbidden"):
		return APIErrorCategoryUnauthorized
	case strings.Contains(message, "invalid"), strings.Contains(message, "malformed"), strings.Contains(message, "missing"), strings.Contains(message, "conflict"):
		return APIErrorCategoryInvalidRequest
	default:
		return APIErrorCategoryUnknown
	}
}

func ClassifyAPIError(err error) APIErrorCategory {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return APIErrorCategoryUnknown
	}
	return apiErr.Category()
}

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type HTTPTransport struct {
	baseURL string
	doer    HTTPDoer
}

func NewHTTPTransport(baseURL string, doer HTTPDoer) (*HTTPTransport, error) {
	if doer == nil {
		return nil, ErrHTTPDoerRequired
	}
	trimmedBaseURL := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmedBaseURL == "" {
		trimmedBaseURL = defaultRegisterBaseURL
	}
	return &HTTPTransport{
		baseURL: trimmedBaseURL,
		doer:    doer,
	}, nil
}

func NewDefaultHTTPTransport() (*HTTPTransport, error) {
	return NewHTTPTransport(defaultRegisterBaseURL, &http.Client{})
}

func (t *HTTPTransport) Do(ctx context.Context, req TransportRequest) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, t.baseURL+buildRegisterPath(req.Path), bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("build http request: %w", err)
	}
	for key, value := range defaultRegisterHeaders {
		httpReq.Header.Set(key, value)
	}
	if req.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.BearerToken)
	}

	resp, err := t.doer.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("do http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read http response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, parseAPIError(resp.StatusCode, body)
	}
	return body, nil
}

func buildRegisterPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || trimmed == "/" {
		return "/" + defaultRegisterAPIVersion
	}
	if strings.HasPrefix(trimmed, "/"+defaultRegisterAPIVersion+"/") || trimmed == "/"+defaultRegisterAPIVersion {
		return trimmed
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return "/" + defaultRegisterAPIVersion + trimmed
}

type apiErrorEnvelope struct {
	Success *bool `json:"success,omitempty"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Messages []string `json:"messages"`
	Error    string   `json:"error"`
	Reason   string   `json:"reason"`
}

func ParseResponse(data []byte) (Response, error) {
	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return Response{}, fmt.Errorf("unmarshal register response: %w", err)
	}
	if apiErr := extractAPIError(http.StatusOK, data); apiErr != nil {
		return Response{}, apiErr
	}
	return resp, nil
}

func parseAPIError(statusCode int, body []byte) error {
	apiErr := extractAPIError(statusCode, body)
	if apiErr == nil {
		return &APIError{StatusCode: statusCode}
	}
	return apiErr
}

func extractAPIError(statusCode int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: statusCode}

	var envelope apiErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		if len(body) == 0 {
			return apiErr
		}
		if statusCode >= http.StatusBadRequest {
			apiErr.Message = strings.TrimSpace(string(body))
			return apiErr
		}
		return nil
	}
	if statusCode < http.StatusBadRequest && (envelope.Success == nil || *envelope.Success) {
		return nil
	}
	if len(envelope.Errors) > 0 {
		apiErr.Code = envelope.Errors[0].Code
		apiErr.Message = strings.TrimSpace(envelope.Errors[0].Message)
		return apiErr
	}
	if len(envelope.Messages) > 0 {
		apiErr.Message = strings.TrimSpace(envelope.Messages[0])
		return apiErr
	}
	if message := strings.TrimSpace(envelope.Error); message != "" {
		apiErr.Message = message
		return apiErr
	}
	if message := strings.TrimSpace(envelope.Reason); message != "" {
		apiErr.Message = message
		return apiErr
	}
	if text := strings.TrimSpace(string(body)); text != "" && statusCode >= http.StatusBadRequest {
		apiErr.Message = text
		return apiErr
	}
	if statusCode >= http.StatusBadRequest || (envelope.Success != nil && !*envelope.Success) {
		return apiErr
	}
	return nil
}
