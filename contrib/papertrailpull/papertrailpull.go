package papertrailpull

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"

	"cloud.google.com/go/datastore"
	stackdriver "cloud.google.com/go/logging"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

const (
	LASTLOGID_KIND      = "last_log_id_papertrail"
	LASTLOGID_KEY       = "last_log_id_papertrail"
	LASTLOGID_NAMESPACE = "last_log_id_papertrail"

	LOGGER_NAME = "papertrailpull"

	PAPERTRAIL_URL = "https://papertrailapp.com/api/v1/events/search.json"
)

var (
	config = &common.Configuration{}

	stackdriverClient *stackdriver.Client
	datastoreClient   *datastore.Client

	PAPERTRAIL_TOKEN string
	PAPERTRAIL_QUERY string
)

func init() {
	mozlogrus.Enable("papertrailpull")
	InitConfig()
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

	stackdriverClient, err = stackdriver.NewClient(context.Background(), config.GCPProjectId)
	if err != nil {
		log.Fatalf("Could not create stackdriver client: %s", err)
	}

	datastoreClient, err = datastore.NewClient(context.Background(), datastore.DetectProjectID)
	if err != nil {
		log.Fatalf("Could not create datastore client: %s", err)
	}

	PAPERTRAIL_TOKEN = config.PapertrailApiToken
	PAPERTRAIL_QUERY = config.PapertrailQuery
}

// Struct for response from Papertrail. MaxIdParsed and MinIdParsed are populated through the `.Parse()` method
type PapertrailSearchResp struct {
	Events      []PapertrailEvent `json:"events"`
	MaxId       string            `json:"max_id"`
	MaxIdParsed int               `json:"-"`
	MinId       string            `json:"min_id"`
	MinIdParsed int               `json:"-"`
}

// Parse MaxId and MinId from strings to ints
func (resp *PapertrailSearchResp) Parse() error {
	var err error

	resp.MaxIdParsed, err = strconv.Atoi(resp.MaxId)
	if err != nil {
		return err
	}

	resp.MinIdParsed, err = strconv.Atoi(resp.MinId)
	if err != nil {
		return err
	}

	return nil
}

// The format of Papertrail log events
type PapertrailEvent struct {
	DisplayReceivedAt string `json:"display_received_at"`
	Facility          string `json:"facility"`
	GeneratedAt       string `json:"generated_at"`
	Hostname          string `json:"hostname"`
	Id                string `json:"id"`
	Message           string `json:"message"`
	Program           string `json:"program"`
	ReceivedAt        string `json:"received_at"`
	Severity          string `json:"severity"`
	SourceId          int    `json:"source_id"`
	SourceIp          string `json:"source_ip"`
	SourceName        string `json:"source_name"`
}

// Structure for last log id that is persisted to Datastore
type lastLogId struct {
	LastLogId int       `json:"last_log_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Function for retrieving `lastLogId` from Datastore.
func loadLastLogId(ctx context.Context) (*lastLogId, error) {
	var (
		sf   common.StateField
		llid lastLogId
	)

	nk := datastore.NameKey(LASTLOGID_KIND, LASTLOGID_KEY, nil)
	nk.Namespace = LASTLOGID_NAMESPACE
	err := datastoreClient.Get(ctx, nk, &sf)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(sf.State), &llid)
	if err != nil {
		return nil, err
	}

	return &llid, nil
}

// Method for persisting `lastLogId` to Datastore
func (llid *lastLogId) save(ctx context.Context) error {
	llid.UpdatedAt = time.Now()
	buf, err := json.Marshal(llid)
	if err != nil {
		return err
	}

	nk := datastore.NameKey(LASTLOGID_KIND, LASTLOGID_KEY, nil)
	nk.Namespace = LASTLOGID_NAMESPACE

	tx, err := datastoreClient.NewTransaction(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.Put(nk, &common.StateField{State: string(buf)}); err != nil {
		return err
	}
	if _, err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// Get the last log id from Papertrail
func getLatestLogEventId() (int, error) {
	logs, err := getLatestPapertrailEvents()
	if err != nil {
		log.Errorf("Error getting latest logs: %s", err)
		return 0, err
	}

	return logs.MaxIdParsed, nil
}

func queryPapertrailSearchApi(url string) (*PapertrailSearchResp, error) {
	client := &http.Client{}
	searchResp := &PapertrailSearchResp{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Papertrail-Token", PAPERTRAIL_TOKEN)
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error requesting events from papertrail: %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading resp body: %s", err)
		return nil, err
	}

	err = json.Unmarshal(b, searchResp)
	if err != nil {
		log.Errorf("Error unmarshalling response from Papertrail: %s", err)
		return nil, err
	}

	err = searchResp.Parse()
	if err != nil {
		log.Errorf("Error parsing max_id and min_id into integers: %s", err)
		return nil, err
	}

	return searchResp, nil
}

func getLatestPapertrailEvents() (*PapertrailSearchResp, error) {
	return queryPapertrailSearchApi(fmt.Sprintf("%s?limit=5&q=%s", PAPERTRAIL_URL, url.QueryEscape(PAPERTRAIL_QUERY)))
}

func getPapertrailEventsFromMinId(minId int) (*PapertrailSearchResp, error) {
	return queryPapertrailSearchApi(fmt.Sprintf("%s?min_id=%d&q=%s", PAPERTRAIL_URL, minId, url.QueryEscape(PAPERTRAIL_QUERY)))
}

// PubSubMessage is used for the function signature of the main function (Papertrailpull())
// represent the data sent from PubSub. The data is not actually read, this is only
// used as a mechanism for triggering the function (using Cloud Scheduler or similiar)
type PubSubMessage struct {
	Data []byte `json:"data"`
}

// Main function ran within the cloudfunction.
func PapertrailPull(ctx context.Context, psmsg PubSubMessage) error {
	llid, err := loadLastLogId(ctx)
	if err != nil {
		log.Errorf("Error loading last log id - Err: %s - Trying to get latest log event from papertrail", err)

		latestlid, err := getLatestLogEventId()
		if err != nil {
			log.Errorf("Failed to get latest log event from papertrail: %s", err)
			return err
		}
		llid = &lastLogId{LastLogId: latestlid, UpdatedAt: time.Now()}
	}

	logger := stackdriverClient.Logger(LOGGER_NAME)

	for {
		resp, err := getPapertrailEventsFromMinId(llid.LastLogId)
		if err != nil {
			log.Errorf("Error getting logs: %s", err)
			break
		}
		if len(resp.Events) == 0 {
			break
		}

		for _, log := range resp.Events {
			logger.Log(stackdriver.Entry{Payload: log})
		}

		log.Infof("papertrailpull logged %d entries", len(resp.Events))
		llid.LastLogId = resp.MaxIdParsed
	}

	err = logger.Flush()
	if err != nil {
		return err
	}

	err = llid.save(ctx)
	if err != nil {
		return err
	}

	return nil
}
