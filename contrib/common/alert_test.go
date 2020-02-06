package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAlert(t *testing.T) {
	a := &Alert{
		Timestamp: time.Now().Add(time.Duration(-5) * time.Minute),
		Metadata: []*AlertMeta{
			{Key: "status", Value: ALERT_NEW},
			{Key: "foo", Value: "bar"},
		},
	}

	assert.True(t, a.IsStatus(ALERT_NEW))
	assert.False(t, a.IsStatus(ALERT_ESCALATED))

	assert.Equal(t, a.GetMetadata("foo"), "bar")
	a.SetMetadata("foo", "different")
	assert.Equal(t, a.GetMetadata("foo"), "different")

	assert.False(t, a.OlderThan(time.Hour))
	assert.True(t, a.OlderThan(time.Minute))
}
