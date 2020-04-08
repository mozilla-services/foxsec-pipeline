package common

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
	"github.com/stretchr/testify/assert"
)

type mockSes struct {
	sesiface.SESAPI
	emailsSent        int
	emailContentsSent []*ses.SendEmailInput
}

const (
	defaultSender    = "testSender@test.com"
	defaultRecipient = "testRecipient@test.com"
)

func (m *mockSes) SendEmail(input *ses.SendEmailInput) (*ses.SendEmailOutput, error) {
	m.emailsSent++
	m.emailContentsSent = append(m.emailContentsSent, input)
	return &ses.SendEmailOutput{}, input.Message.Validate()
}

func TestSend911Email(t *testing.T) {
	expectedMsg := "{\n  Destination: {\n    CcAddresses: [\"testCc@test.com\"],\n    ToAddresses: [\"testRecipient@test.com\"]\n  },\n  Message: {\n    Body: {\n      Text: {\n        Charset: \"UTF-8\",\n        Data: \"summoner on slack raised a secops911 with the message: help! emergency!\"\n      }\n    },\n    Subject: {\n      Charset: \"UTF-8\",\n      Data: \"[foxsec-alert] Secops 911 from summoner via slack\"\n    }\n  },\n  Source: \"testSender@test.com\"\n}"
	mSes := mockSes{}
	sesClient := SESClient{
		sesClient:              &mSes,
		senderEmail:            defaultSender,
		defaultEscalationEmail: defaultRecipient,
	}
	sesClient.Send911Email("summoner", "testCc@test.com", "help! emergency!")
	assert.Equal(t, 1, mSes.emailsSent)
	c := mSes.emailContentsSent[0]
	assert.Equal(t, expectedMsg, c.String())
}

func TestSend911EmailWithEmptyCC(t *testing.T) {
	expectedMsg := "{\n  Destination: {\n    CcAddresses: [],\n    ToAddresses: [\"testRecipient@test.com\"]\n  },\n  Message: {\n    Body: {\n      Text: {\n        Charset: \"UTF-8\",\n        Data: \"summoner on slack raised a secops911 with the message: help! emergency!\"\n      }\n    },\n    Subject: {\n      Charset: \"UTF-8\",\n      Data: \"[foxsec-alert] Secops 911 from summoner via slack\"\n    }\n  },\n  Source: \"testSender@test.com\"\n}"
	mSes := mockSes{}
	sesClient := SESClient{
		sesClient:              &mSes,
		senderEmail:            defaultSender,
		defaultEscalationEmail: defaultRecipient,
	}
	sesClient.Send911Email("summoner", "", "help! emergency!")
	assert.Equal(t, 1, mSes.emailsSent)
	c := mSes.emailContentsSent[0]
	assert.Equal(t, expectedMsg, c.String())
}

func TestEscalationEmail(t *testing.T) {
	expectedMsg := "{\n  Destination: {\n    CcAddresses: [],\n    ToAddresses: [\"testRecipient@test.com\"]\n  },\n  Message: {\n    Body: {\n      Text: {\n        Charset: \"UTF-8\",\n        Data: \"Id: \\nSummary: \\nSeverity: \\nCategory: \\nTimestamp: 2001-01-01 01:01:01.000000001 +0000 UTC\\nMetadata:\\n - status=NEW\\n - foo=bar\\n\\nPayload (message sent to user):\\n\\n\"\n      }\n    },\n    Subject: {\n      Charset: \"UTF-8\",\n      Data: \"[foxsec-alert] Escalating alert - \"\n    }\n  },\n  Source: \"testSender@test.com\"\n}"
	mSes := mockSes{}
	sesClient := SESClient{
		sesClient:              &mSes,
		senderEmail:            defaultSender,
		defaultEscalationEmail: defaultRecipient,
	}
	alert := &Alert{
		Timestamp: time.Date(2001, time.January, 1, 1, 1, 1, 1, time.UTC),
		Metadata: []*AlertMeta{
			{Key: "status", Value: ALERT_NEW},
			{Key: "foo", Value: "bar"},
		},
	}
	sesClient.SendEscalationEmail(alert)
	assert.Equal(t, 1, mSes.emailsSent)
	c := mSes.emailContentsSent[0]
	assert.Equal(t, expectedMsg, c.String())

}
