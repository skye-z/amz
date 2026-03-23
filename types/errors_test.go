package types_test

import (
	"errors"
	"testing"

	"github.com/skye-z/amz/types"
)

// 验证基础错误可以被 errors.Is 识别。
func TestCommonErrors(t *testing.T) {
	if !errors.Is(types.ErrInvalidConfig, types.ErrInvalidConfig) {
		t.Fatal("expected ErrInvalidConfig to match itself")
	}
	if !errors.Is(types.ErrUnsupportedMode, types.ErrUnsupportedMode) {
		t.Fatal("expected ErrUnsupportedMode to match itself")
	}
	if !errors.Is(types.ErrNotImplemented, types.ErrNotImplemented) {
		t.Fatal("expected ErrNotImplemented to match itself")
	}
}
