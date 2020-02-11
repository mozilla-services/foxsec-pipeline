package slackbotbackground

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/mozilla-services/foxsec-pipeline/contrib/slackbot-background/internal"
	"github.com/nlopes/slack"
	"github.com/stretchr/testify/assert"
)

var _ = (func() interface{} {
	_testing = true

	return nil
}())

const SlackProfileGetURL = "https://slack.com/api/users.profile.get"
const SampleUser = `{
    "ok": true,
    "profile": {
        "avatar_hash": "ge3b51ca72de",
        "status_text": "Print is dead",
        "status_emoji": ":books:",
        "status_expiration": 0,
        "real_name": "Egon Spengler",
        "display_name": "spengler",
        "real_name_normalized": "Egon Spengler",
        "display_name_normalized": "spengler",
        "email": "spengler@ghostbusters.example.com",
        "image_original": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_24": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_32": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_48": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_72": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_192": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "image_512": "https://.../avatar/e3b51ca72dee4ef87916ae2b9240df50.jpg",
        "team": "T012AB3C4"
    }
}`

func setupTest() (*internal.FakeMailer, *internal.FakeTransport) {
	fakeMailer := &internal.FakeMailer{}
	fakeTransport := internal.NewFakeTransport()
	client = internal.NewTestClient(fakeTransport)
	globals.slackClient = slack.New("testtoken", slack.OptionHTTPClient(client))
	globals.sesClient = fakeMailer
	return fakeMailer, fakeTransport
}
func TestSuccessfulSecOps911WithUnknownUser(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/secops911", "ResponseURL": "responseurl", "Text": "testing", "UserID": "123"}}`
	psmsg := &pubsub.Message{
		Data: []byte(data),
	}

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.Nil(t, err)

	// check 911 email was sent and not other escalations
	assert.Equal(t, 1, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 2)
	assert.Contains(t, fakeTransport.RequestURLs, SlackProfileGetURL)
	assert.Contains(t, fakeTransport.RequestURLs, "responseurl")
	assert.Contains(t, fakeMailer.ArgList911callers, "unknown user")
	assert.Contains(t, fakeMailer.ArgList911messages, "testing")
}

func TestSuccessfulSecOps911WithKnownUser(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/secops911", "ResponseURL": "responseurl", "Text": "who you gonna call", "UserID": "123"}}`
	psmsg := &pubsub.Message{
		Data: []byte(data),
	}
	fakeTransport.AddHandler(SlackProfileGetURL, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(SampleUser)),
			Header:     make(http.Header),
		}, nil
	})

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.Nil(t, err)

	// check 911 email was sent and not other escalations
	assert.Equal(t, 1, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 2)
	assert.Contains(t, fakeTransport.RequestURLs, "https://slack.com/api/users.profile.get")
	assert.Contains(t, fakeTransport.RequestURLs, "responseurl")
	assert.Contains(t, fakeMailer.ArgList911callers, "Egon Spengler (spengler@ghostbusters.example.com)")
	assert.Contains(t, fakeMailer.ArgList911messages, "who you gonna call")
}

func TestSuccessfulStagingSecOps911WithUnknownUser(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/staging_secops911", "ResponseURL": "responseurl", "Text": "testing", "UserID": "123"}}`
	psmsg := &pubsub.Message{
		Data: []byte(data),
	}

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.Nil(t, err)

	// check 911 email was sent and not other escalations
	assert.Equal(t, 1, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 2)
	assert.Contains(t, fakeTransport.RequestURLs, SlackProfileGetURL)
	assert.Contains(t, fakeTransport.RequestURLs, "responseurl")
	assert.Contains(t, fakeMailer.ArgList911callers, "unknown user")
	assert.Contains(t, fakeMailer.ArgList911messages, "testing")
}

func TestSuccessfulStagingSecOps911WithKnownUser(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/staging_secops911", "ResponseURL": "responseurl", "Text": "who you gonna call", "UserID": "123"}}`
	psmsg := &pubsub.Message{
		Data: []byte(data),
	}
	fakeTransport.AddHandler(SlackProfileGetURL, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(SampleUser)),
			Header:     make(http.Header),
		}, nil
	})

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.Nil(t, err)

	// check 911 email was sent and not other escalations
	assert.Equal(t, 1, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 2)
	assert.Contains(t, fakeTransport.RequestURLs, "https://slack.com/api/users.profile.get")
	assert.Contains(t, fakeTransport.RequestURLs, "responseurl")
	assert.Contains(t, fakeMailer.ArgList911callers, "Egon Spengler (spengler@ghostbusters.example.com)")
	assert.Contains(t, fakeMailer.ArgList911messages, "who you gonna call")
}

func TestUnsupportedSlashCommand(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/fakeCommand", "ResponseURL": "responseurl", "Text": "testing", "UserID": "123"}}`
	psmsg := &pubsub.Message{
		Data: []byte(data),
	}

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.NotNil(t, err)
	assert.Errorf(t, err, "Unsupported slash command")

	// check no emails sent and no requests were made
	assert.Equal(t, 0, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 0)
}
