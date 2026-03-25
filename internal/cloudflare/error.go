package cloudflare

import (
	"errors"
	"fmt"
)

var (
	ErrCompat               = errors.New("cloudflare compatibility error")
	ErrAuthenticationFailed = errors.New("authentication failed")
)

type CompatError struct {
	Operation string
	Quirk     string
	Cause     error
}

func (e *CompatError) Error() string {
	if e == nil {
		return ErrCompat.Error()
	}
	if e.Cause == nil {
		return fmt.Sprintf("%s: operation=%s quirk=%s", ErrCompat, e.Operation, e.Quirk)
	}
	return fmt.Sprintf("%s: operation=%s quirk=%s: %v", ErrCompat, e.Operation, e.Quirk, e.Cause)
}

func (e *CompatError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *CompatError) Is(target error) bool { return target == ErrCompat }

func WrapError(operation, quirk string, cause error) error {
	return &CompatError{Operation: operation, Quirk: quirk, Cause: cause}
}
