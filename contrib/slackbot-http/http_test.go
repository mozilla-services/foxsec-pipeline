package slackbothttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"

	"cloud.google.com/go/pubsub"
	"github.com/stretchr/testify/assert"
)

var _ = (func() interface{} {
	_testing = true

	return nil
}())

var (
	interactionBody  = []byte("payload={\"type\":\"interactive_message\",\"team\":{\"id\":\"T0CAG\",\"domain\":\"acme-creamery\"},\"user\":{\"id\":\"U0CA5\",\"username\":\"Amy McGee\",\"name\":\"Amy McGee\",\"team_id\":\"T3MDE\"},\"api_app_id\":\"A0CA5\",\"token\":\"Shh_its_a_seekrit\",\"container\":{\"type\":\"message\",\"text\":\"The contents of the original message where the action originated\"},\"trigger_id\":\"12466734323.1395872398\",\"response_url\":\"https://www.postresponsestome.com/T123567/1509734234\",\"actions\":[{\"name\":\"foo\",\"value\":\"yes\"}]}")
	slashCommandBody = []byte("token=gIkuvaNzQIHg97ATvDxqgjtO&team_id=T0001&team_domain=example&enterprise_id=E0001&enterprise_name=Globular%20Construct%20Inc&channel_id=C2147483705&channel_name=test&user_id=U2147483697&user_name=Steve&command=/weather&text=94070&response_url=https://hooks.slack.com/commands/1234/5678&trigger_id=13345224609.738474920.8088930838d88f008e0")
	SECRET           = "abcdefg12345"
)

func createHeaders(body []byte) http.Header {
	h := http.Header{}
	currentTime := time.Now().Unix()
	hash := hmac.New(sha256.New, []byte(SECRET))
	hash.Write([]byte(fmt.Sprintf("v0:%d:%s", currentTime, body)))
	h.Set("X-Slack-Signature", "v0="+hex.EncodeToString(hash.Sum(nil)))
	h.Set("X-Slack-Request-Timestamp", fmt.Sprintf("%d", currentTime))
	return h
}

func TestSlackbotHTTP(t *testing.T) {
	var err error
	pubsubClient, err = pubsub.NewClient(context.Background(), "testing")
	assert.NoError(t, err)
	config.SlackbotTriggerTopicName = "slackbothttp-testing"
	config.SlackSigningSecret = SECRET

	topic, err := pubsubClient.CreateTopic(context.Background(), config.SlackbotTriggerTopicName)
	assert.NoError(t, err)

	// Create a new subscription to the previously created topic
	// with the given name.
	sub, err := pubsubClient.CreateSubscription(context.Background(), "slackbothttp-sub", pubsub.SubscriptionConfig{
		Topic:            topic,
		AckDeadline:      10 * time.Second,
		ExpirationPolicy: 5 * time.Minute,
	})
	assert.NoError(t, err)

	// Test params/body
	tests := []struct {
		body           io.Reader
		header         http.Header
		expectData     bool
		expectedAction common.ActionType
	}{
		{
			body:           bytes.NewReader(interactionBody),
			header:         createHeaders(interactionBody),
			expectData:     true,
			expectedAction: common.Interaction,
		},
		{
			body:           bytes.NewReader(slashCommandBody),
			header:         createHeaders(slashCommandBody),
			expectData:     true,
			expectedAction: common.SlashCommand,
		},
		{
			body:       nil,
			header:     http.Header{},
			expectData: false,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("POST", "/", test.body)
		assert.NoError(t, err)
		req.Header = test.header
		if test.expectedAction == common.SlashCommand {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(SlackbotHTTP)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, rr.Code, http.StatusOK)

		gotData := false

		seen := make(chan int, 1)
		ctxWithTimeout, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				select {
				case <-seen:
				case <-time.After(3 * time.Second):
					cancel()
					return
				}
			}
		}()

		err = sub.Receive(ctxWithTimeout, func(ctx context.Context, m *pubsub.Message) {
			seen <- 1
			assert.True(t, test.expectData)
			td, err := common.PubSubMessageToTriggerData(*m)
			assert.NoError(t, err)
			assert.Equal(t, td.Action, test.expectedAction)
			gotData = true
			m.Ack()
		})
		if err == context.Canceled {
			assert.False(t, test.expectData)
		}

		assert.Equal(t, gotData, test.expectData)
	}
}
