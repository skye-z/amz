package amz

import "errors"

var (
	ErrNoRuntimeEnabled = errors.New("at least one runtime must be enabled")
	ErrClientClosed     = errors.New("client already closed")
)
