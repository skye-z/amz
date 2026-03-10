package types

import "fmt"

// CloudflareCompatError 描述兼容层在特定协议场景中附加的错误上下文。
type CloudflareCompatError struct {
	Operation string
	Quirk     string
	Cause     error
}

// Error 返回包含操作与兼容场景的最小错误信息。
func (e *CloudflareCompatError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause == nil {
		return fmt.Sprintf("%s: %s", e.Operation, e.Quirk)
	}
	return fmt.Sprintf("%s: %s: %v", e.Operation, e.Quirk, e.Cause)
}

// Unwrap 允许调用方透传到底层原因错误。
func (e *CloudflareCompatError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is 允许兼容层错误被统一哨兵值识别。
func (e *CloudflareCompatError) Is(target error) bool {
	return target == ErrCloudflareCompat
}

// WrapCloudflareError 为兼容层场景附加最小上下文。
func WrapCloudflareError(operation, quirk string, cause error) error {
	return &CloudflareCompatError{
		Operation: operation,
		Quirk:     quirk,
		Cause:     cause,
	}
}
