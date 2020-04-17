package common

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAlert(t *testing.T) {
	a := &Alert{
		Timestamp: time.Now().Add(time.Duration(-5) * time.Minute),
		Metadata: []*AlertMeta{
			{Key: META_STATUS, Value: ALERT_NEW},
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

var (
	exampleGuarddutyAlert          = []byte(`{"severity": "critical","id": "test","summary": "test summary","category": "gatekeeper:aws","timestamp": "2020-03-19T21:44:21.062Z","metadata": [{"key": "aws_account_id","value": "XXXXXX"},{"key": "aws_account_name","value": "xxx-xxx-xx"},{"key": "aws_region","value": "us-west-1"},{"key": "description","value": "EC2 instance i-99999999 is behaving in a manner that may indicate it is being used to perform a Denial of Service (DoS) attack using DNS protocol."},{"key": "finding_aws_severity","value": "8.0"},{"key": "finding_type","value": "Backdoor:EC2/DenialOfService.Dns"},{"key": "finding_id","value": "123456789"},{"key": "url_to_finding","value": "https://us-west-1.console.aws.amazon.com/guardduty/home?region=us-west-1#/findings?fId=123456789"},{"key": "alert_handling_severity","value": "low"},{"key": "monitored_resource","value": "gatekeeper"}]}`)
	exampleGuarddutyAlertFormatted = `#### Core Alert Info
Finding Type: Backdoor:EC2/DenialOfService.Dns
Finding URL: https://us-west-1.console.aws.amazon.com/guardduty/home?region=us-west-1#/findings?fId=123456789
Finding ID: 123456789
AWS Account Name: xxx-xxx-xx
AWS Account ID: XXXXXX
Finding Description: EC2 instance i-99999999 is behaving in a manner that may indicate it is being used to perform a Denial of Service (DoS) attack using DNS protocol.

#### Fraud Pipeline Info
Id: test
Summary: test summary
Severity: critical
Category: gatekeeper:aws
Timestamp: 2020-03-19 21:44:21.062 +0000 UTC

#### Metadata
 - aws_account_id=XXXXXX
 - aws_account_name=xxx-xxx-xx
 - aws_region=us-west-1
 - description=EC2 instance i-99999999 is behaving in a manner that may indicate it is being used to perform a Denial of Service (DoS) attack using DNS protocol.
 - finding_aws_severity=8.0
 - finding_type=Backdoor:EC2/DenialOfService.Dns
 - finding_id=123456789
 - url_to_finding=https://us-west-1.console.aws.amazon.com/guardduty/home?region=us-west-1#/findings?fId=123456789
 - alert_handling_severity=low
 - monitored_resource=gatekeeper

`
)

func TestAlertFormatting(t *testing.T) {
	var gdAlert *Alert
	err := json.Unmarshal(exampleGuarddutyAlert, &gdAlert)
	assert.NoError(t, err)
	md := gdAlert.MarkdownFormat()
	assert.Equal(t, md, exampleGuarddutyAlertFormatted)
}
