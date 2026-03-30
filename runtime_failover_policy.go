package amz

import "github.com/skye-z/amz/internal/failure"

type runtimeFailureClass = failure.Class
type runtimeFailoverAction = failure.Action
type runtimeFailoverDecision = failure.Decision

const (
	runtimeFailureClassUnknown      = failure.ClassUnknown
	runtimeFailureClassAuth         = failure.ClassAuth
	runtimeFailureClassProtocol     = failure.ClassProtocol
	runtimeFailureClassRateLimited  = failure.ClassRateLimited
	runtimeFailureClassRoute        = failure.ClassRoute
	runtimeFailureClassTransport    = failure.ClassTransport
	runtimeFailureClassTunnelHealth = failure.ClassTunnelHealth
	runtimeFailureClassCanceled     = failure.ClassCanceled

	runtimeFailoverActionIgnore         = failure.ActionIgnore
	runtimeFailoverActionSwitchEndpoint = failure.ActionSwitchEndpoint
)

func classifyRuntimeFailure(err error) runtimeFailoverDecision {
	return failure.Classify(failure.Event{Err: err})
}
