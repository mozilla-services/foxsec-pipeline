package internal

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"
)

// FakeTransport is a roundtripper that can used with httpclient to write unit tests
type FakeTransport struct {
	RequestURLs    []string
	urlMap         map[string]func(req *http.Request) (*http.Response, error)
	defaultHandler func(req *http.Request) (*http.Response, error)
}

// RoundTrip .
func (f *FakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.RequestURLs = append(f.RequestURLs, req.URL.String())
	urlHandler := f.urlMap[req.URL.String()]
	if urlHandler != nil {
		return urlHandler(req)
	}
	return f.defaultHandler(req)
}

// AddHandler installs a handler for a specific url
func (f *FakeTransport) AddHandler(url string, handler interface{}) {
	f.urlMap[url] = handler.(func(req *http.Request) (*http.Response, error))
}

// NewFakeTransport creates a faketransport that default returns 200s
func NewFakeTransport() *FakeTransport {
	return &FakeTransport{
		urlMap:         make(map[string]func(req *http.Request) (*http.Response, error)),
		defaultHandler: Return200,
	}
}

// Return200 returns an http response with a dummy body and statuscode 200
func Return200(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewBufferString(`OK`)),
		Header:     make(http.Header),
	}, nil
}

//NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
	}
}

// FakeMailer is a mock for the escalation mailer
type FakeMailer struct {
	Num911Sent         int
	NumEscalationsSent int
	ArgList911callers  []string
	ArgList911cc       []string
	ArgList911messages []string
}

// SendEscalationEmail simply increments an internal counter of how many escalations we've sent
func (f *FakeMailer) SendEscalationEmail(alert *common.Alert) error {
	f.NumEscalationsSent++
	return nil
}

// Send911Email records the 911 escalation emails we've sent out
func (f *FakeMailer) Send911Email(caller string, ccAddress string, message string) error {
	f.Num911Sent++
	f.ArgList911callers = append(f.ArgList911callers, caller)
	f.ArgList911messages = append(f.ArgList911messages, message)
	f.ArgList911cc = append(f.ArgList911cc, ccAddress)
	return nil
}

// DefaultEscalationEmail returns the email address of the fake emailer
func (f *FakeMailer) DefaultEscalationEmail() string {
	return "default"
}
