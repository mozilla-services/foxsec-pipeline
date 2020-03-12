package common

import (
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/pubsub"
)

const (
	ALERT_NEW          = "NEW"
	ALERT_ACKNOWLEDGED = "ACKNOWLEDGED"
	ALERT_ESCALATED    = "ESCALATED"

	ESCALATE_TO = "escalate_to"
)

type Alert struct {
	Id        string       `json:"id"`
	Severity  string       `json:"severity"`
	Category  string       `json:"category"`
	Summary   string       `json:"summary"`
	Payload   string       `json:"payload"`
	Metadata  []*AlertMeta `json:"metadata"`
	Timestamp time.Time    `json:"timestamp"`
}

type AlertMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (a *Alert) PrettyPrint() string {
	var md string
	for _, am := range a.Metadata {
		md = md + fmt.Sprintf(" - %s=%s\n", am.Key, am.Value)
	}
	s := fmt.Sprintf(`Id: %s
Summary: %s
Severity: %s
Category: %s
Timestamp: %s
Metadata:
%s
Payload (message sent to user):
%s
`,
		a.Id, a.Summary, a.Severity, a.Category, a.Timestamp, md, a.Payload)
	return s
}

func (a *Alert) OlderThan(dur time.Duration) bool {
	return a.Timestamp.Add(dur).Before(time.Now())
}

func (a *Alert) IsStatus(s string) bool {
	for _, am := range a.Metadata {
		if am.Key == "status" {
			return am.Value == s
		}
	}
	return false
}

func (a *Alert) GetMetadata(key string) string {
	for _, am := range a.Metadata {
		if am.Key == key {
			return am.Value
		}
	}
	return ""
}

func (a *Alert) SetMetadata(key, value string) {
	for _, am := range a.Metadata {
		if am.Key == key {
			am.Value = value
			return
		}
	}
	a.Metadata = append(a.Metadata, &AlertMeta{Key: key, Value: value})
}

func PubSubMessageToAlerts(psmsg pubsub.Message) ([]*Alert, error) {
	var alerts []*Alert
	err := json.Unmarshal(psmsg.Data, &alerts)
	if err != nil {
		return nil, err
	}
	return alerts, nil
}
