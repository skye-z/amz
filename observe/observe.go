package observe

import "github.com/skye-z/amz/types"

type Stats = types.Stats
type Event = types.Event
type EventHandler = types.EventHandler
type StructuredStats = types.StructuredStats
type LifecycleStats = types.LifecycleStats
type TrafficStats = types.TrafficStats
type TimingStats = types.TimingStats

func SanitizeText(text string) string {
	return types.SanitizeText(text)
}

func SanitizeError(err error) string {
	return types.SanitizeError(err)
}
