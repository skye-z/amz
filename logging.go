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

type eventDescription struct {
	action  string
	message string
}

var eventDescriptions = map[string]eventDescription{
	"managed_runtime:new.success":                 {action: "INIT", message: "initialized managed runtime"},
	"managed_runtime:new.failed":                  {action: "INIT", message: "failed to initialize managed runtime"},
	"managed_runtime:start.begin":                 {action: "START", message: "starting managed runtime"},
	"managed_runtime:start.reuse_runtime":         {action: "START", message: "reusing existing runtime"},
	"managed_runtime:start.success":               {action: "START", message: "managed runtime started"},
	"managed_runtime:start.failed":                {action: "START", message: "managed runtime failed to start"},
	"managed_runtime:auth.ensure.begin":           {action: "REGISTER", message: "preparing registration state"},
	"managed_runtime:auth.ensure.success":         {action: "REGISTER", message: "registration state ready"},
	"managed_runtime:auth.ensure.failed":          {action: "REGISTER", message: "failed to prepare registration state"},
	"managed_runtime:endpoint.select.begin":       {action: "SELECT", message: "selecting endpoint"},
	"managed_runtime:endpoint.plan.ready":         {action: "SELECT", message: "prepared candidate plan"},
	"managed_runtime:endpoint.probe_profile":      {action: "SELECT", message: "using endpoint probe profile"},
	"managed_runtime:endpoint.select.success":     {action: "SELECT", message: "selected endpoint"},
	"managed_runtime:endpoint.select.failed":      {action: "SELECT", message: "failed to select endpoint"},
	"managed_runtime:endpoint.failover":           {action: "SELECT", message: "failing over to next endpoint"},
	"managed_runtime:endpoint.probe.begin":        {action: "SELECT", message: "probing candidate"},
	"managed_runtime:endpoint.probe.success":      {action: "SELECT", message: "probe finished"},
	"managed_runtime:endpoint.probe.failed":       {action: "SELECT", message: "probe failed"},
	"managed_runtime:endpoint.warp_check.begin":   {action: "SELECT", message: "checking warp availability"},
	"managed_runtime:endpoint.warp_check.success": {action: "SELECT", message: "warp availability confirmed"},
	"managed_runtime:endpoint.warp_check.failed":  {action: "SELECT", message: "warp availability failed"},
	"managed_runtime:state.save.begin":            {action: "STATE", message: "saving runtime state"},
	"managed_runtime:state.save.success":          {action: "STATE", message: "saved runtime state"},
	"managed_runtime:state.save.failed":           {action: "STATE", message: "failed to save runtime state"},
	"managed_runtime:runtime.build.begin":         {action: "BUILD", message: "building runtime"},
	"managed_runtime:runtime.build.success":       {action: "BUILD", message: "built runtime"},
	"managed_runtime:runtime.build.failed":        {action: "BUILD", message: "failed to build runtime"},
	"managed_runtime:runtime.start.begin":         {action: "CONNECT", message: "connecting runtime"},
	"managed_runtime:runtime.start.success":       {action: "CONNECT", message: "runtime connected"},
	"managed_runtime:runtime.start.failed":        {action: "CONNECT", message: "runtime connection failed"},
	"managed_runtime:runtime.health.failed":       {action: "HEALTH", message: "runtime health check failed"},
	"managed_runtime:runtime.close.failed":        {action: "CLOSE", message: "failed to close runtime"},
	"managed_runtime:runtime.failover.begin":      {action: "FAILOVER", message: "starting runtime failover"},
	"managed_runtime:runtime.failover.success":    {action: "FAILOVER", message: "runtime failover succeeded"},
	"managed_runtime:runtime.failover.failed":     {action: "FAILOVER", message: "runtime failover failed"},
	"managed_runtime:run.begin":                   {action: "RUN", message: "running managed runtime"},
	"managed_runtime:run.success":                 {action: "RUN", message: "managed runtime finished"},
	"managed_runtime:run.failed":                  {action: "RUN", message: "managed runtime run failed"},
	"managed_runtime:run.skipped":                 {action: "RUN", message: "skipped managed runtime run"},
	"managed_runtime:close.begin":                 {action: "CLOSE", message: "closing managed runtime"},
	"managed_runtime:close.success":               {action: "CLOSE", message: "managed runtime closed"},
	"managed_runtime:close.failed":                {action: "CLOSE", message: "managed runtime close failed"},
	"managed_runtime:close.skipped":               {action: "CLOSE", message: "skipped managed runtime close"},
	"client:new.success":                          {action: "INIT", message: "created client"},
	"client:new.failed":                           {action: "INIT", message: "failed to create client"},
	"client:start.begin":                          {action: "START", message: "starting client"},
	"client:start.success":                        {action: "START", message: "client started"},
	"client:start.failed":                         {action: "START", message: "client failed to start"},
	"client:run.begin":                            {action: "RUN", message: "running client"},
	"client:run.success":                          {action: "RUN", message: "client finished"},
	"client:run.failed":                           {action: "RUN", message: "client run failed"},
	"client:close.begin":                          {action: "CLOSE", message: "closing client"},
	"client:close.success":                        {action: "CLOSE", message: "client closed"},
	"client:close.failed":                         {action: "CLOSE", message: "client close failed"},
	"client:close.skipped":                        {action: "CLOSE", message: "skipped client close"},
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
	l.base.Printf("%s [%s] %s", currentLogTimestamp(), normalizeAction(l.action), message)
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
	if description, ok := eventDescriptions[component+":"+event]; ok {
		return description.action, description.message
	}
	return "INFO", strings.ReplaceAll(event, ".", " ")
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
