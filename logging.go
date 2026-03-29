package amz

import (
	"fmt"
	"strings"
	"time"
)

// Logger is the minimal public logging contract for amz.
// It is compatible with standard log.Logger and the internal runtime logger.
type Logger interface {
	Printf(format string, args ...any)
}

type logField struct {
	key   string
	value any
}

type phaseLogger struct {
	base   Logger
	action string
}

func field(key string, value any) logField {
	return logField{key: key, value: value}
}

func durationField(key string, value time.Duration) logField {
	return logField{key: key, value: value.String()}
}

func withAction(logger Logger, action string) Logger {
	if logger == nil {
		return nil
	}
	action = normalizeAction(action)
	if wrapped, ok := logger.(*phaseLogger); ok {
		if wrapped.action == action {
			return logger
		}
		return &phaseLogger{base: wrapped.base, action: action}
	}
	return &phaseLogger{base: logger, action: action}
}

func (l *phaseLogger) Printf(format string, args ...any) {
	if l == nil || l.base == nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	l.base.Printf("[%s] %s %s", normalizeAction(l.action), currentLogTimestamp(), message)
}

func logEvent(logger Logger, component, event string, fields ...logField) {
	action, message := describeEvent(component, event)
	logger = withAction(logger, action)
	if logger == nil {
		return
	}

	var b strings.Builder
	b.Grow(64 + len(fields)*24)
	b.WriteString(message)
	for _, item := range fields {
		if strings.TrimSpace(item.key) == "" {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(item.key)
		b.WriteByte('=')
		b.WriteString(formatLogValue(item.value))
	}
	logger.Printf("%s", b.String())
}

func currentLogTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05.000")
}

func describeEvent(component, event string) (action string, message string) {
	switch component + ":" + event {
	case "managed_runtime:new.success":
		return "INIT", "initialized managed runtime"
	case "managed_runtime:new.failed":
		return "INIT", "failed to initialize managed runtime"
	case "managed_runtime:start.begin":
		return "START", "starting managed runtime"
	case "managed_runtime:start.reuse_runtime":
		return "START", "reusing existing runtime"
	case "managed_runtime:start.success":
		return "START", "managed runtime started"
	case "managed_runtime:start.failed":
		return "START", "managed runtime failed to start"
	case "managed_runtime:auth.ensure.begin":
		return "REGISTER", "preparing registration state"
	case "managed_runtime:auth.ensure.success":
		return "REGISTER", "registration state ready"
	case "managed_runtime:auth.ensure.failed":
		return "REGISTER", "failed to prepare registration state"
	case "managed_runtime:endpoint.select.begin":
		return "SELECT", "selecting endpoint"
	case "managed_runtime:endpoint.select.success":
		return "SELECT", "selected endpoint"
	case "managed_runtime:endpoint.select.failed":
		return "SELECT", "failed to select endpoint"
	case "managed_runtime:state.save.begin":
		return "STATE", "saving runtime state"
	case "managed_runtime:state.save.success":
		return "STATE", "saved runtime state"
	case "managed_runtime:state.save.failed":
		return "STATE", "failed to save runtime state"
	case "managed_runtime:runtime.build.begin":
		return "BUILD", "building runtime"
	case "managed_runtime:runtime.build.success":
		return "BUILD", "built runtime"
	case "managed_runtime:runtime.build.failed":
		return "BUILD", "failed to build runtime"
	case "managed_runtime:runtime.start.begin":
		return "CONNECT", "connecting runtime"
	case "managed_runtime:runtime.start.success":
		return "CONNECT", "runtime connected"
	case "managed_runtime:runtime.start.failed":
		return "CONNECT", "runtime connection failed"
	case "managed_runtime:run.begin":
		return "RUN", "running managed runtime"
	case "managed_runtime:run.success":
		return "RUN", "managed runtime finished"
	case "managed_runtime:run.failed":
		return "RUN", "managed runtime run failed"
	case "managed_runtime:run.skipped":
		return "RUN", "skipped managed runtime run"
	case "managed_runtime:close.begin":
		return "CLOSE", "closing managed runtime"
	case "managed_runtime:close.success":
		return "CLOSE", "managed runtime closed"
	case "managed_runtime:close.failed":
		return "CLOSE", "managed runtime close failed"
	case "managed_runtime:close.skipped":
		return "CLOSE", "skipped managed runtime close"
	case "client:new.success":
		return "INIT", "created client"
	case "client:new.failed":
		return "INIT", "failed to create client"
	case "client:start.begin":
		return "START", "starting client"
	case "client:start.success":
		return "START", "client started"
	case "client:start.failed":
		return "START", "client failed to start"
	case "client:run.begin":
		return "RUN", "running client"
	case "client:run.success":
		return "RUN", "client finished"
	case "client:run.failed":
		return "RUN", "client run failed"
	case "client:close.begin":
		return "CLOSE", "closing client"
	case "client:close.success":
		return "CLOSE", "client closed"
	case "client:close.failed":
		return "CLOSE", "client close failed"
	case "client:close.skipped":
		return "CLOSE", "skipped client close"
	default:
		return "INFO", strings.ReplaceAll(event, ".", " ")
	}
}

func normalizeAction(action string) string {
	action = strings.ToUpper(strings.TrimSpace(action))
	if action == "" {
		return "INFO"
	}
	return action
}

func formatLogValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		return fmt.Sprintf("%q", v)
	case error:
		return fmt.Sprintf("%q", v.Error())
	case bool:
		if v {
			return "true"
		}
		return "false"
	case time.Duration:
		return fmt.Sprintf("%q", v.String())
	default:
		return fmt.Sprint(v)
	}
}
