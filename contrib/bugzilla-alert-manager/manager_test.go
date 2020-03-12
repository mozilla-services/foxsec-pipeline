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
)

func generateTestAlerts() pubsub.Message {
	lowSevAlert := &common.Alert{
		Id:        "lowtestunique",
		Category:  "gatekeeper:aws",
		Summary:   "test low sev alert",
		Metadata:  []*common.AlertMeta{{Key: "alert_handling_severity", Value: "low"}},
		Timestamp: time.Now().Add(-5 * time.Minute),
	}
	highSevAlert := &common.Alert{
		Id:        "hightestunique",
		Category:  "gatekeeper:aws",
		Summary:   "test high sev alert",
		Metadata:  []*common.AlertMeta{{Key: "alert_handling_severity", Value: "high"}},
		Timestamp: time.Now().Add(-6 * time.Minute),
	}
	buf, err := json.Marshal([]*common.Alert{lowSevAlert, highSevAlert})
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
				w.Write([]byte(`{"bugs":[{"id": 99, "creation_time": "2020-01-01T13:50:04Z"}]}`))
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
	// init needed globals and DB
	server := createMockServer(t)
	client := pagerduty.NewClient("testkey", pagerduty.WithAPIEndpoint(server.URL))
	globals.pagerdutyClient = client
	bugzillaConfig := common.BugzillaConfig{
		AlertConfigs: map[string]common.BugzillaAlertConfig{
			"gatekeeper:aws": {TrackerBugId: "123"},
		},
	}

	globals.bugzillaClient = common.NewBugzillaClient(bugzillaConfig, server.URL)

	config.PagerdutyTicketDutyScheduleId = "1"

	// Start test
	testAlerts := generateTestAlerts()
	err = BugzillaAlertManager(ctx, testAlerts)
	assert.NoError(t, err)
	assert.Equal(t, 1, pdCnt)
	assert.Equal(t, 1, searchBugCnt)
	assert.Equal(t, 1, createBugCnt)
	assert.Equal(t, 0, commentBugCnt)

	// Since a bug exsists for today, this should add the
	// low sev alert as a comment.
	moreTestAlerts := generateTestAlerts()
	err = BugzillaAlertManager(ctx, moreTestAlerts)
	assert.NoError(t, err)
	assert.Equal(t, 1, pdCnt)
	assert.Equal(t, 2, searchBugCnt)
	assert.Equal(t, 1, createBugCnt)
	assert.Equal(t, 1, commentBugCnt)

	// Clean-up
	server.Close()
}
