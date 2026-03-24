package observe

import (
	"fmt"

	"github.com/skye-z/amz/config"
)

func Logf(logger config.Logger, format string, args ...any) {
	if logger == nil {
		return
	}

	original := fmt.Sprintf(format, args...)
	maskedArgs := SanitizeArgs(args)
	masked := fmt.Sprintf(format, maskedArgs...)
	masked = SanitizeText(masked)
	if masked != original {
		logger.Printf(masked)
		return
	}
	logger.Printf(SanitizeText(format), maskedArgs...)
}

func SanitizeArgs(args []any) []any {
	if len(args) == 0 {
		return nil
	}
	masked := make([]any, len(args))
	for i, arg := range args {
		if text, ok := arg.(string); ok {
			masked[i] = SanitizeText(text)
			continue
		}
		if err, ok := arg.(error); ok {
			masked[i] = SanitizeError(err)
			continue
		}
		masked[i] = arg
	}
	return masked
}
