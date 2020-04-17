package bugzilla_alert_manager

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"

	"cloud.google.com/go/functions/metadata"
	"cloud.google.com/go/pubsub"
	"github.com/PagerDuty/go-pagerduty"
	"github.com/stretchr/testify/assert"
)

var _ = (func() interface{} {
	_testing = true

	return nil
}())

var (
	pdCnt         int
	createBugCnt  int
	commentBugCnt int
	searchBugCnt  int
	updateBugCnt  int
)

func generateLowSevTestAlert() pubsub.Message {
	lowSevAlert := &common.Alert{
		Id:        "lowtestunique",
		Category:  "gatekeeper:aws",
		Summary:   "test low sev alert",
		Metadata:  []*common.AlertMeta{{Key: common.META_ALERT_HANDLING_SEVERITY, Value: "low"}},
		Timestamp: time.Now().Add(-5 * time.Minute),
	}
	buf, err := json.Marshal(lowSevAlert)
	if err != nil {
		panic(err)
	}
	return pubsub.Message{Data: buf}
}

func generateHighSevTestAlert() pubsub.Message {
	highSevAlert := &common.Alert{
		Id:        "hightestunique",
		Category:  "gatekeeper:aws",
		Summary:   "test high sev alert",
		Metadata:  []*common.AlertMeta{{Key: common.META_ALERT_HANDLING_SEVERITY, Value: "high"}},
		Timestamp: time.Now().Add(-6 * time.Minute),
	}
	buf, err := json.Marshal(highSevAlert)
	if err != nil {
		panic(err)
	}
	return pubsub.Message{Data: buf}
}

func createMockServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	// Pagerduty Mock
	mux.HandleFunc("/schedules/1/users", func(w http.ResponseWriter, r *http.Request) {
		pdCnt++
		w.Write([]byte(`{"users": [{"id": "1", "email": "testuser@example.com"}]}`))
	})
	mux.HandleFunc("/oncalls", func(w http.ResponseWriter, r *http.Request) {
		pdCnt++
		w.Write([]byte(`{
			"oncalls": [
			  {
				"escalation_policy": {
				  "id": "P9OFD2O",
				  "type": "escalation_policy_reference",
				  "summary": "Default",
				  "self": "https://api.pagerduty.com/escalation_policies/P9OFD2O",
				  "html_url": "https://apidocs.pagerduty.com/escalation_policies/P9OFD2O"
				},
				"escalation_level": 1,
				"schedule": null,
				"user": {
				  "name": "John Doe",
				  "email": "john.doe@example.com",
				  "time_zone": "America/Los_Angeles",
				  "color": "purple",
				  "avatar_url": "https://secure.gravatar.com/avatar/8eb1b522f60d11fa897de1dc6351b7e8.png?d=mm&r=PG",
				  "billed": true,
				  "role": "owner",
				  "description": null,
				  "invitation_sent": false,
				  "job_title": null,
				  "teams": [],
				  "contact_methods": [
					{
					  "id": "P1NJL34",
					  "type": "email_contact_method_reference",
					  "summary": "Default",
					  "self": "https://api.pagerduty.com/users/PPC00ZX/contact_methods/P1NJL34",
					  "html_url": null
					}
				  ],
				  "notification_rules": [
					{
					  "id": "P29AUSK",
					  "type": "assignment_notification_rule_reference",
					  "summary": "0 minutes: channel P1NJL34",
					  "self": "https://api.pagerduty.com/users/PPC00ZX/notification_rules/P29AUSK",
					  "html_url": null
					},
					{
					  "id": "PQ4XWX0",
					  "type": "assignment_notification_rule_reference",
					  "summary": "0 minutes: channel P1NJL34",
					  "self": "https://api.pagerduty.com/users/PPC00ZX/notification_rules/PQ4XWX0",
					  "html_url": null
					}
				  ],
				  "coordinated_incidents": [],
				  "id": "PPC00ZX",
				  "type": "user",
				  "summary": "John Doe",
				  "self": "https://api.pagerduty.com/users/PPC00ZX",
				  "html_url": "https://apidocs.pagerduty.com/users/PPC00ZX"
				},
				"start": null,
				"end": null
			  }]}`))
	})

	// Bugzilla Comment Mock
	mux.HandleFunc("/rest/bug/1/comment", func(w http.ResponseWriter, r *http.Request) {
		commentBugCnt++
		body, err := ioutil.ReadAll(r.Body)
		assert.NoError(t, err)
		defer r.Body.Close()
		cc := &common.CreateComment{}
		err = json.Unmarshal(body, cc)
		assert.NoError(t, err)
		assert.Contains(t, cc.Comment, "lowtestunique")
		assert.NotContains(t, cc.Comment, "hightestunique")
	})

	// Bugzilla Update Bug Mock
	mux.HandleFunc("/rest/bug/1", func(w http.ResponseWriter, r *http.Request) {
		updateBugCnt++
		body, err := ioutil.ReadAll(r.Body)
		assert.NoError(t, err)
		defer r.Body.Close()
		ub := &common.UpdateBugReq{}
		err = json.Unmarshal(body, ub)
		assert.NoError(t, err)
		assert.Equal(t, ub.Status, common.ASSIGNED)
	})

	// Bugzilla Bug Mock
	mux.HandleFunc("/rest/bug", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			createBugCnt++
			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(t, err)
			defer r.Body.Close()
			cb := &common.CreateBug{}
			err = json.Unmarshal(body, cb)
			assert.NoError(t, err)
			assert.Equal(t, cb.Product, "TEST_PRODUCT")
			assert.Contains(t, cb.Summary, "gatekeeper:aws alerts")
			assert.Contains(t, cb.Description, "lowtestunique")
			assert.NotContains(t, cb.Description, "hightestunique")
			assert.Equal(t, cb.Blocks, "123")
			w.Write([]byte(`{"id": 1}`))
		}
		// Search bugs
		if r.Method == http.MethodGet {
			searchBugCnt++
			if searchBugCnt == 1 {
				w.Write([]byte(`{"bugs":[{"id": 99, "creation_time": "2020-01-01T13:50:04Z", "is_open": false}]}`))
			} else {
				b, err := json.Marshal(&common.SearchBugResponse{
					Bugs: []common.BugResp{
						{
							Id:           1,
							CreationTime: time.Now(),
							AssignedTo:   "testuser@example.com",
						},
					},
				})
				assert.NoError(t, err)
				w.Write(b)
			}
		}
	})

	return server
}

func TestBugzillaAlertManager(t *testing.T) {
	var err error
	ctx := metadata.NewContext(context.Background(), &metadata.Metadata{
		Timestamp: time.Now(),
		EventID:   "1234567890",
	})
	// init needed globals
	err = config.LoadFrom("test_config.yaml")
	assert.NoError(t, err)
	server := createMockServer(t)
	client := pagerduty.NewClient("testkey", pagerduty.WithAPIEndpoint(server.URL))
	globals.pagerdutyClient = client
	globals.bugzillaClient = common.NewBugzillaClient(config.BugzillaConfig, server.URL)

	// Start test with high sev
	err = BugzillaAlertManager(ctx, generateHighSevTestAlert())
	assert.NoError(t, err)
	assert.Equal(t, 0, pdCnt)
	assert.Equal(t, 0, searchBugCnt)
	assert.Equal(t, 0, createBugCnt)
	assert.Equal(t, 0, commentBugCnt)
	assert.Equal(t, 0, updateBugCnt)

	err = BugzillaAlertManager(ctx, generateLowSevTestAlert())
	assert.NoError(t, err)
	assert.Equal(t, 1, pdCnt)
	assert.Equal(t, 1, searchBugCnt)
	assert.Equal(t, 1, createBugCnt)
	assert.Equal(t, 0, commentBugCnt)
	assert.Equal(t, 0, updateBugCnt)

	// Since a bug exsists for today, this should add the
	// low sev alert as a comment.
	err = BugzillaAlertManager(ctx, generateLowSevTestAlert())
	assert.NoError(t, err)
	assert.Equal(t, 1, pdCnt)
	assert.Equal(t, 2, searchBugCnt)
	assert.Equal(t, 1, createBugCnt)
	assert.Equal(t, 1, commentBugCnt)
	assert.Equal(t, 1, updateBugCnt)

	// Clean-up
	server.Close()
}
