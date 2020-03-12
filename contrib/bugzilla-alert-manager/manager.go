package bugzilla_alert_manager

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"time"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"

	"cloud.google.com/go/functions/metadata"
	"cloud.google.com/go/pubsub"
	"github.com/PagerDuty/go-pagerduty"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var (
	globals Globals
	DB      *common.DBClient

	config = &common.Configuration{}

	// Support retries for events for a told of 30 seconds.
	EXPIRATION = time.Second * 30

	// dirty hack to disable init in unit tests
	_testing = false
)

func init() {
	if _testing {
		return
	}
	mozlogrus.Enable("bugzilla-alert-manager")
	InitConfig()

	PROJECT_ID := os.Getenv("GCP_PROJECT")
	var err error
	DB, err = common.NewDBClient(context.Background(), PROJECT_ID)
	if err != nil {
		log.Fatalf("Error creating db client: %s", err)
		return
	}
}

func InitConfig() {
	log.Info("Starting up...")
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		log.Fatal("$CONFIG_PATH must be set.")
	}
	err := config.LoadFrom(configPath)
	if err != nil {
		log.Fatalf("Could not load config file from `%s`: %s", configPath, err)
	}

	globals.pagerdutyClient = pagerduty.NewClient(config.PagerdutyAuthToken)
	globals.bugzillaClient = common.NewBugzillaClient(config.BugzillaConfig, "https://bugzilla.mozilla.org")
}

type Globals struct {
	pagerdutyClient *pagerduty.Client
	bugzillaClient  *common.BugzillaClient
}

func userOnTicketDuty() (string, error) {
	users, err := globals.pagerdutyClient.ListOnCallUsers(config.PagerdutyTicketDutyScheduleId, pagerduty.ListOnCallUsersOptions{})
	if err != nil {
		log.Errorf("Error getting pagerduty schedule: %s. Using default %s", err, globals.bugzillaClient.Config.DefaultAssignedTo)
		return globals.bugzillaClient.Config.DefaultAssignedTo, nil
	}
	if len(users) == 0 {
		log.Errorf("No oncall user found for schedule %s! Using default %s", config.PagerdutyTicketDutyScheduleId, globals.bugzillaClient.Config.DefaultAssignedTo)
		return globals.bugzillaClient.Config.DefaultAssignedTo, nil
	}
	return users[0].Email, nil
}

func createNewBug(alertCollection *AlertCollection) error {
	assignedTo, err := userOnTicketDuty()
	if err != nil {
		log.Errorf("Couldn't get user on ticket duty: %s", err)
		return err
	}
	_, err = globals.bugzillaClient.CreateBugFromAlerts(assignedTo, alertCollection.category, alertCollection.alerts)
	return err
}

func BugzillaAlertManager(ctx context.Context, psmsg pubsub.Message) error {
	meta, err := metadata.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("metadata.FromContext: %v", err)
	}

	// Ignore events that are too old.
	expiration := meta.Timestamp.Add(EXPIRATION)
	if time.Now().After(expiration) {
		log.Errorf("Event Timeout: stopping retries for expired event '%q'", meta.EventID)
		return nil
	}

	alerts, err := common.PubSubMessageToAlerts(psmsg)
	if err != nil {
		log.Errorf("Error decoding pubsub message: %s", err)
		return nil
	}

	// Filter out "high" severity alerts with metadata key "alert_handling_severity"
	var lowSeverityAlerts []*common.Alert
	var alertIds []string
	for _, alert := range alerts {
		if alert.GetMetadata("alert_handling_severity") == "low" {
			lowSeverityAlerts = append(lowSeverityAlerts, alert)
			alertIds = append(alertIds, alert.Id)
		}
	}

	if len(lowSeverityAlerts) == 0 {
		return nil
	}

	contextLogger := log.WithFields(log.Fields{"alert_ids": alertIds})

	collections := CreateCollections(lowSeverityAlerts)

	for _, collection := range collections {
		searchValues := url.Values{}
		searchValues.Add("whiteboard", collection.category)
		searchResp, err := globals.bugzillaClient.SearchBugs(searchValues)
		if err != nil {
			contextLogger.Errorf("Error from bug searching: %s", err)
			continue
		}
		if len(searchResp.Bugs) != 0 {
			sort.Sort(searchResp)
			newestBug := searchResp.Bugs[0]
			// Was the bug created today?
			ny, nm, nd := time.Now().Date()
			y, m, d := newestBug.CreationTime.Date()
			if (ny == y) && (nm == m) && (nd == d) {
				// Add to bug
				err := globals.bugzillaClient.AddAlertsToBug(newestBug.Id, collection.alerts)
				if err != nil {
					contextLogger.Errorf("Error adding comment to bug %d: %s", newestBug.Id, err)
					return err
				}
				continue
			}
		}

		// Create new bug
		err = createNewBug(collection)
		if err != nil {
			contextLogger.Errorf("Error creating new bug: %s", err)
			return err
		}
	}

	return nil
}
