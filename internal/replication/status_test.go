package replication

import (
	"testing"
	"time"
)

func TestStatusEvaluate(t *testing.T) {
	start := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	interval := 30 * time.Second
	for _, item := range []struct {
		name   string
		status Status
		now    time.Time
		health Health
		lag    time.Duration
	}{
		{"nothing uploaded yet", Status{StartedAt: start, Interval: interval}, start.Add(10 * time.Second), HealthPending, 10 * time.Second},
		{"just synced", Status{StartedAt: start, Interval: interval, LastSyncedAt: start.Add(time.Second), LastCycleAt: start.Add(time.Second)}, start.Add(11 * time.Second), HealthCurrent, 10 * time.Second},
		// An idle database keeps the bucket current without new uploads.
		{"idle after sync", Status{StartedAt: start, Interval: interval, LastSyncedAt: start, LastCycleAt: start.Add(time.Hour)}, start.Add(time.Hour + 5*time.Second), HealthCurrent, 5 * time.Second},
		{"cycles stopped", Status{StartedAt: start, Interval: interval, LastSyncedAt: start, LastCycleAt: start}, start.Add(2 * time.Minute), HealthLagging, 2 * time.Minute},
		// A failing cycle is not evidence of currency, even if recent.
		{"failing after a sync", Status{StartedAt: start, Interval: interval, LastSyncedAt: start, LastCycleAt: start.Add(time.Hour), ConsecutiveFails: 2}, start.Add(time.Hour), HealthFailing, time.Hour},
		{"failing from the start", Status{StartedAt: start, Interval: interval, LastCycleAt: start.Add(time.Minute), ConsecutiveFails: 1}, start.Add(time.Minute), HealthFailing, time.Minute},
	} {
		health, lag := item.status.Evaluate(item.now)
		if health != item.health || lag != item.lag {
			t.Errorf("%s: health=%s lag=%s, want %s %s", item.name, health, lag, item.health, item.lag)
		}
	}
}
