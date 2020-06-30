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

	// Support retries for events for up to 3 minutes before expiring
	EXPIRATION = time.Minute * 3

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
	globals.environment = "dev"
	if config.Environment != "" {
		globals.environment = config.Environment
	}
}

type Globals struct {
	pagerdutyClient *pagerduty.Client
	bugzillaClient  *common.BugzillaClient
	environment     string
}

func userOnTicketDuty() (string, error) {
	opts := pagerduty.ListOnCallOptions{
		ScheduleIDs: []string{config.PagerdutyTicketDutyScheduleId},
		Includes:    []string{"users"},
	}
	resp, err := globals.pagerdutyClient.ListOnCalls(opts)
	if err != nil {
		log.Errorf("Error getting pagerduty schedule: %s. Using default %s", err, globals.bugzillaClient.Config.DefaultAssignedTo)
		return globals.bugzillaClient.Config.DefaultAssignedTo, nil
	}
	if resp.OnCalls == nil || len(resp.OnCalls) == 0 {
		log.Errorf("No oncall user found for schedule %s! Using default %s", config.PagerdutyTicketDutyScheduleId, globals.bugzillaClient.Config.DefaultAssignedTo)
		return globals.bugzillaClient.Config.DefaultAssignedTo, nil
	}
	if resp.OnCalls[0].User.Email == "" {
		log.Errorf("Oncall found, but no email for user %s for schedule %s! Using default %s", resp.OnCalls[0].User.Summary, config.PagerdutyTicketDutyScheduleId, globals.bugzillaClient.Config.DefaultAssignedTo)
		return globals.bugzillaClient.Config.DefaultAssignedTo, nil
	}
	return resp.OnCalls[0].User.Email, nil
}

func createNewBug(alert *common.Alert) error {
	assignedTo, err := userOnTicketDuty()
	if err != nil {
		log.Errorf("Couldn't get user on ticket duty: %s", err)
		return err
	}
	log.Infof("Creating new %s bug assigned to %s", alert.Category, assignedTo)
	_, err = globals.bugzillaClient.CreateBugFromAlerts(assignedTo, alert.Category, []*common.Alert{alert})
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

	alert, err := common.PubSubMessageToAlert(psmsg)
	if err != nil {
		log.Errorf("Error decoding pubsub message: %s", err)
		return nil
	}

	// Append the env to the alert category.
	alert.Category = fmt.Sprintf("%s-%s", alert.Category, globals.environment)

	// Check if we should process this alert
	if alert.GetMetadata(common.META_ALERT_HANDLING_SEVERITY) != "low" {
		return nil
	}
	if _, ok := globals.bugzillaClient.Config.CategoryToTracker[alert.Category]; !ok {
		return nil
	}

	contextLogger := log.WithFields(log.Fields{"alert_id": alert.Id})
	contextLogger.Infof("Handling %s", alert.Id)

	searchValues := url.Values{}
	searchValues.Add("whiteboard", alert.Category)
	searchResp, err := globals.bugzillaClient.SearchBugs(searchValues)
	if err != nil {
		contextLogger.Errorf("Error from bug searching: %s", err)
	} else {
		if searchResp != nil && len(searchResp.Bugs) != 0 {
			sort.Sort(searchResp)
			newestBug := searchResp.Bugs[len(searchResp.Bugs)-1]
			// Was the bug created today?
			ny, nm, nd := time.Now().Date()
			y, m, d := newestBug.CreationTime.Date()
			if (ny == y) && (nm == m) && (nd == d) {
				contextLogger.Infof("Adding %s to bugzilla bug %d", alert.Id, newestBug.Id)
				// If bug is closed, re-open
				if !newestBug.IsOpen {
					err := globals.bugzillaClient.UpdateBug(newestBug.Id, &common.UpdateBugReq{Status: common.ASSIGNED})
					if err != nil {
						log.Errorf("Error re-opening closed bug: %s", err)
					}
				}
				// Add to bug
				err := globals.bugzillaClient.AddAlertsToBug(newestBug.Id, []*common.Alert{alert})
				if err != nil {
					contextLogger.Errorf("Error adding comment to bug %d: %s", newestBug.Id, err)
					return err
				}
				return nil
			}
		}
	}

	// Create new bug
	contextLogger.Info("Creating new bug")
	err = createNewBug(alert)
	if err != nil {
		contextLogger.Errorf("Error creating new bug: %s", err)
		return err
	}

	return nil
}
