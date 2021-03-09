package slackbotbackground

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/mozilla-services/foxsec-pipeline/contrib/common"
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

const Iprepd1Url = "http://www.iprepd1.com"
const Iprepd2Url = "http://www.iprepd2.com"

func setupTest() (*internal.FakeMailer, *internal.FakeTransport) {
	fakeMailer := &internal.FakeMailer{}
	fakeTransport := internal.NewFakeTransport()
	client = internal.NewTestClient(fakeTransport)
	globals.slackClient = slack.New("testtoken", slack.OptionHTTPClient(client))
	globals.sesClient = fakeMailer
	config.EmergencyCcEmail = "cc@test.com"
	globals.personsClient = &internal.FakePersonsClient{}
	config.AllowedLDAPGroups = []string{"test"}
	config.IprepdInstances = []common.IprepdInstance{common.IprepdInstance{URL: Iprepd1Url, APIKey: "key"}, common.IprepdInstance{URL: Iprepd2Url, APIKey: "key"}}
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
	assert.Contains(t, fakeMailer.ArgList911cc, "cc@test.com")
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

func TestCheckIprepdCommandWithReputation(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/check_email", "ResponseURL": "responseurl", "Text": "test@example.com", "UserID": "123"}}`
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
	repData := `{"object":"test@example.com","type":"email","reputation":0,"reviewed":false,"lastupdated":"2021-02-27T00:31:18.187326761Z","decayafter":"2021-03-06T00:31:18.187324497Z"}`
	url1 := fmt.Sprintf("%s%s", Iprepd1Url, "/type/email/test@example.com")
	url2 := fmt.Sprintf("%s%s", Iprepd2Url, "/type/email/test@example.com")

	fakeTransport.AddHandler(url1, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(repData)),
			Header:     make(http.Header),
		}, nil
	})
	fakeTransport.AddHandler(url2, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(repData)),
			Header:     make(http.Header),
		}, nil
	})

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.Nil(t, err)
	// check no emails sent and no requests were made
	assert.Equal(t, 0, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 4)
	assert.Len(t, fakeTransport.Requests, 4)

	msg, err := ioutil.ReadAll(fakeTransport.Requests[3].Body)
	expectedMsg := "{\"text\":\"object=test@example.com\\nhttp://www.iprepd1.com - {\\\"object\\\":\\\"test@example.com\\\",\\\"type\\\":\\\"email\\\",\\\"reputation\\\":0,\\\"reviewed\\\":false,\\\"lastupdated\\\":\\\"2021-02-27T00:31:18.187326761Z\\\",\\\"decayafter\\\":\\\"2021-03-06T00:31:18.187324497Z\\\"}\\nhttp://www.iprepd2.com - {\\\"object\\\":\\\"test@example.com\\\",\\\"type\\\":\\\"email\\\",\\\"reputation\\\":0,\\\"reviewed\\\":false,\\\"lastupdated\\\":\\\"2021-02-27T00:31:18.187326761Z\\\",\\\"decayafter\\\":\\\"2021-03-06T00:31:18.187324497Z\\\"}\\n\",\"replace_original\":false,\"delete_original\":false,\"blocks\":null}"
	assert.Equal(t, expectedMsg, string(msg))
}

func TestCheckIprepdCommandMissingReputation(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/check_email", "ResponseURL": "responseurl", "Text": "test@example.com", "UserID": "123"}}`
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
	url1 := fmt.Sprintf("%s%s", Iprepd1Url, "/type/email/test@example.com")
	url2 := fmt.Sprintf("%s%s", Iprepd2Url, "/type/email/test@example.com")

	fakeTransport.AddHandler(url1, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 404,
			Header:     make(http.Header),
		}, nil
	})
	fakeTransport.AddHandler(url2, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 404,
			Header:     make(http.Header),
		}, nil
	})

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.Nil(t, err)
	// check no emails sent and no requests were made
	assert.Equal(t, 0, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 4)

	msg, err := ioutil.ReadAll(fakeTransport.Requests[3].Body)
	expectedMsg := "{\"text\":\"object=test@example.com\\nhttp://www.iprepd1.com - Not found! (Assumed reputation: 100)\\nhttp://www.iprepd2.com - Not found! (Assumed reputation: 100)\\n\",\"replace_original\":false,\"delete_original\":false,\"blocks\":null}"
	assert.Equal(t, expectedMsg, string(msg))
}

func TestCheckIprepdCommandError(t *testing.T) {
	fakeMailer, fakeTransport := setupTest()
	data := `{"action_type": "slash_command", "slash_command": {"Cmd": "/check_email", "ResponseURL": "responseurl", "Text": "test@example.com", "UserID": "123"}}`
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
	url1 := fmt.Sprintf("%s%s", Iprepd1Url, "/type/email/test@example.com")
	url2 := fmt.Sprintf("%s%s", Iprepd2Url, "/type/email/test@example.com")

	fakeTransport.AddHandler(url1, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 500,
			Header:     make(http.Header),
		}, nil
	})
	fakeTransport.AddHandler(url2, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 500,
			Header:     make(http.Header),
		}, nil
	})

	err := SlackbotBackground(context.Background(), *psmsg)

	assert.Nil(t, err)
	// check no emails sent and no requests were made
	assert.Equal(t, 0, fakeMailer.Num911Sent)
	assert.Equal(t, 0, fakeMailer.NumEscalationsSent)
	assert.Len(t, fakeTransport.RequestURLs, 4)

	msg, err := ioutil.ReadAll(fakeTransport.Requests[3].Body)
	expectedMsg := "{\"text\":\"object=test@example.com\\nhttp://www.iprepd1.com - Error retrieving results!\\nhttp://www.iprepd2.com - Error retrieving results!\\n\",\"replace_original\":false,\"delete_original\":false,\"blocks\":null}"
	assert.Equal(t, expectedMsg, string(msg))
}
