package duopull

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"cloud.google.com/go/datastore"
	stackdriver "cloud.google.com/go/logging"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

const (
	_ = iota
	debugOff
	debugDuo
	debugGCP
)

var debug = debugOff

const (
	ADMIN_ENDPOINT     = "/admin/v1/logs/administrator"
	AUTH_ENDPOINT      = "/admin/v2/logs/authentication"
	TELEPHONY_ENDPOINT = "/admin/v1/logs/telephony"

	LOGGER_NAME = "duopull"

	MINTIME_KIND      = "mintime"
	MINTIME_KEY       = "mintime"
	MINTIME_NAMESPACE = "mintime"
)

var (
	PROJECT_ID string
	KEYNAME    string

	cfg config
)

func init() {
	mozlogrus.Enable("duopull")
	PROJECT_ID = os.Getenv("GCP_PROJECT")
	KEYNAME = os.Getenv("KMS_KEYNAME")

	if os.Getenv("DEBUGDUO") == "1" {
		debug = debugDuo
	}
	if os.Getenv("DEBUGGCP") == "1" {
		if debug != debugOff {
			log.Fatal("DEBUGDUO and DEBUGGCP cannot both be set")
		}
		debug = debugGCP
	}

	if debug != debugDuo {
		if PROJECT_ID == "" {
			log.Fatal("GCP_PROJECT must be set (when running locally)")
		}
		if KEYNAME == "" {
			log.Fatal("KEYNAME must be set")
		}
	}

	err := cfg.init()
	if err != nil {
		log.Fatalf("config.init() errored: %s", err)
	}
}

// config is the global configuration structure for the function
type config struct {
	// Set from environment
	duoAPIHost string // Duo API hostname
	duoIKey    string // Duo API ikey
	duoSKey    string // Duo API skey

	// Allocated during initialization
	duo               *duoInterface // Duo authorization header generator
	stackdriverClient *stackdriver.Client
	datastoreClient   *datastore.Client
}

// init loads configuration from the environment
func (c *config) init() error {
	kms, err := common.NewKMSClient()
	if err != nil {
		if debug != debugDuo {
			log.Fatalf("Could not create kms client. Err: %s", err)
		} else {
			kms = &common.KMSClient{}
		}
	}

	c.duoAPIHost = os.Getenv("DUOPULL_HOST")
	c.duoIKey, err = kms.DecryptEnvVar(KEYNAME, "DUOPULL_IKEY")
	if err != nil {
		log.Fatalf("Could not decrypt duopull ikey. Err: %s", err)
	}
	c.duoSKey, err = kms.DecryptEnvVar(KEYNAME, "DUOPULL_SKEY")
	if err != nil {
		log.Fatalf("Could not decrypt duopull skey. Err: %s", err)
	}

	err = c.validate()
	if err != nil {
		return err
	}

	if debug != debugDuo {
		c.stackdriverClient, err = stackdriver.NewClient(context.Background(), PROJECT_ID)
		if err != nil {
			return err
		}
		c.datastoreClient, err = datastore.NewClient(context.Background(), PROJECT_ID)
		if err != nil {
			return err
		}
	}

	if debug != debugGCP {
		c.duo = &duoInterface{
			apiHost: cfg.duoAPIHost,
			iKey:    cfg.duoIKey,
			sKey:    cfg.duoSKey,
		}
	}

	return nil
}

// validate verifies the config structure is valid given the operating mode
func (c *config) validate() error {
	if debug != debugGCP {
		if c.duoAPIHost == "" {
			return fmt.Errorf("DUOPULL_HOST must be set")
		}
		if c.duoIKey == "" {
			return fmt.Errorf("DUOPULL_IKEY must be set")
		}
		if c.duoSKey == "" {
			return fmt.Errorf("DUOPULL_SKEY must be set")
		}
	}
	return nil
}

// duoInterface is used to generate Authorization headers for requests to the Duo API
type duoInterface struct {
	apiHost string
	iKey    string
	sKey    string
}

// getAuthHeader returns an authentication header and date string header for use in a request
// to the Duo API.
func (d *duoInterface) getAuthHeader(method, path string, params map[string]string) (string, string) {
	ds := time.Now().UTC().Format("Mon, 2 Jan 2006 15:04:05 -0700")

	c := []string{
		ds,
		strings.ToUpper(method),
		strings.ToLower(d.apiHost),
		path,
	}
	paramval := url.Values{}
	for k, v := range params {
		paramval.Add(k, v)
	}
	c = append(c, paramval.Encode())
	template := strings.Join(c, "\n")

	h := hmac.New(sha1.New, []byte(d.sKey))
	h.Write([]byte(template))

	auth := fmt.Sprintf("%v:%v", d.iKey, hex.EncodeToString(h.Sum(nil)))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth)), ds
}

// logRecords represents a response for a log request from the Duo API.
//
// The actual event information is treated as arbitrary JSON. The stat field is
// specifically included so we can inspect the value to confirm the request was
// successful.
//
// See also https://duo.com/docs/adminapi#api-details
type logRecords struct {
	Stat     string        `json:"stat"`
	Response []interface{} `json:"response"`
}

// authV2Records represents a response for an auth log request from the V2 Duo API.
//
// See also https://duo.com/docs/adminapi#authentication-logs
type authV2Records struct {
	Stat     string                `json:"stat"`
	Response authV2RecordsResponse `json:"response"`
}

// authV2RecordsResponse functions exactly like logRecords.Response
type authV2RecordsResponse struct {
	Authlogs []interface{} `json:"authlogs"`
}

// emitEvent is an event which will be submitted to Stackdriver
//
// Since the event itself contains no reference to the class of the event (e.g., authentication,
// administrator, etc) the path used to request the log is included here so the event types
// can be differentiated by the stream consumer.
type emitEvent struct {
	Path  string      `json:"path"`  // The request path (e.g., /api/v1/logs/telephony)
	Event interface{} `json:"event"` // The actual event
}

func (e *emitEvent) toInterface() (map[string]interface{}, error) {
	ret := make(map[string]interface{})
	buf, err := json.Marshal(e)
	if err != nil {
		return ret, err
	}
	err = json.Unmarshal(buf, &ret)
	return ret, err
}

// getTimestamp extracts the timestamp value from e as an integer
func (e *emitEvent) getTimestamp() (int, error) {
	// Define a pseudo-struct for extraction of the timestamp instead of using
	// type assertions and dealing with float64 conversion
	type pse struct {
		Timestamp int `json:"timestamp"`
	}
	var p pse
	buf, err := json.Marshal(e.Event)
	if err != nil {
		return 0, err
	}
	err = json.Unmarshal(buf, &p)
	if err != nil {
		return 0, err
	}
	if p.Timestamp == 0 {
		return 0, fmt.Errorf("event had no timestamp")
	}
	return p.Timestamp, nil
}

// emitter stores all collected events for distribution
type emitter struct {
	events []emitEvent
}

// emit batches collected events to the configured Stackdriver logger
func (e *emitter) emit() error {
	if debug == debugDuo { // Duo debug, just write events to stdout
		for _, v := range e.events {
			cv, err := v.toInterface()
			if err != nil {
				log.Error(err)
				continue
			}
			out, err := toMozLog(cv)
			if err != nil {
				log.Error(err)
				continue
			}
			buf, err := json.Marshal(out)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Infof("%v\n", string(buf))
		}
		return nil
	}

	logger := cfg.stackdriverClient.Logger(LOGGER_NAME)

	for _, v := range e.events {
		cv, err := v.toInterface()
		if err != nil {
			log.Infof("Raw event: %v", v)
			log.Errorf("Can't convert to interface: %s", err)
			continue
		}
		out, err := toMozLog(cv)
		if err != nil {
			log.Infof("Raw event as an interface: %v", cv)
			log.Errorf("Can't convert to moz log: %s", err)
			continue
		}
		e, err := json.Marshal(out)
		if err != nil {
			log.Infof("Raw event converted to MozLog: %v", out)
			log.Errorf("Can't marshall event to json: %s", err)
			continue
		}
		logger.Log(stackdriver.Entry{Payload: json.RawMessage(e)})
	}

	err := logger.Flush()
	if err != nil {
		return err
	}

	return nil
}

// minTime stores state related to the mintime parameter for the Duo API logging
// endpoints
type minTime struct {
	Administrator  int `json:"administrator"`  // mintime for administrator logs
	Authentication int `json:"authentication"` // mintime for authentication logs
	Telephony      int `json:"telephony"`      // mintime for telephony logs
}

// load pulls mintime state information from datastore
func (m *minTime) load(ctx context.Context) error {
	if debug == debugDuo {
		// Duo debug, just set an offset timestamp from current time for testing
		// purposes instead of loading it
		m.Administrator = int(time.Now().Add(-1 * (time.Minute * 60)).Unix())
		m.Authentication = m.Administrator
		m.Telephony = m.Administrator
		return nil
	}
	var sf common.StateField
	nk := datastore.NameKey(MINTIME_KIND, MINTIME_KEY, nil)
	nk.Namespace = MINTIME_NAMESPACE
	err := cfg.datastoreClient.Get(ctx, nk, &sf)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(sf.State), m)
	if err != nil {
		return err
	}

	return nil
}

// save stores mintime state information
func (m *minTime) save(ctx context.Context) error {
	if debug == debugDuo { // Duo debug, noop
		return nil
	}

	buf, err := json.Marshal(m)
	if err != nil {
		return err
	}

	nk := datastore.NameKey(MINTIME_KIND, MINTIME_KEY, nil)
	nk.Namespace = MINTIME_NAMESPACE

	tx, err := cfg.datastoreClient.NewTransaction(ctx)
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

func flatten(in map[string]interface{}, out map[string]interface{}, prefix []string) error {
	for k, v := range in {
		ak := k
		if len(prefix) > 0 {
			ak = fmt.Sprintf("%v_%v", strings.Join(prefix, "_"), ak)
		}
		switch reflect.ValueOf(v).Kind() {
		case reflect.Map:
			t0, ok := v.(map[string]interface{})
			if !ok {
				return fmt.Errorf("type assertion failed flattening map value")
			}
			err := flatten(t0, out, append(prefix, k))
			if err != nil {
				return err
			}
		case reflect.Slice, reflect.Array:
			t0, ok := v.([]interface{})
			if !ok {
				return fmt.Errorf("type assertion failed flattening slice value")
			}
			if len(t0) == 0 {
				break
			}
			arrayval := make([]interface{}, 0)
			for _, x := range t0 {
				k := reflect.ValueOf(x).Kind()
				if k == reflect.Array || k == reflect.Slice || k == reflect.Map ||
					k == reflect.Struct {
					// If it's an array of maps/slices/etc, we wont handle
					// it
					return fmt.Errorf("can't handle slice containing complex types")
				}
				arrayval = append(arrayval, x)
			}
			out[ak] = arrayval
		default:
			out[ak] = v
		}
	}
	return nil
}

func toMozLog(in interface{}) (interface{}, error) {
	var ret interface{}
	buf := make(map[string]interface{})
	cv, ok := in.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("type assertion failed on input event")
	}

	// Duo logging will store JSON data structures as strings in the log response,
	// specifically with the event description field. Convert that into a
	// structure here.
	if x, ok := cv["event"]; ok {
		if y, ok := x.(map[string]interface{}); ok {
			if z, ok := y["description"]; ok {
				if zs, ok := z.(string); ok {
					ndesc := make(map[string]interface{})
					err := json.Unmarshal([]byte(zs), &ndesc)
					if err == nil { // on error, leave original intact
						y["description"] = ndesc
					}
				}
			}
		}
	}

	err := flatten(cv, buf, []string{})
	if err != nil {
		return nil, err
	}
	l := log.New()
	l.Formatter = &mozlogrus.MozLogFormatter{LoggerName: "duopull", Type: "app.log"}
	bbuf := bytes.NewBuffer([]byte{})
	l.Out = bbuf
	l.WithFields(buf).Info("duopull event")
	err = json.Unmarshal(bbuf.Bytes(), &ret)
	return ret, err
}

// sendLogRequest is a small helper function for sending requests to Duo's API and
// returning the response body.
func sendLogRequest(req *http.Request) ([]byte, error) {
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned code %v with body %s", resp.StatusCode, b)
	}
	return b, nil
}

// logRequest makes a request for logs from the Duo API from mintime onwards, using the
// specified API endpoint path for the request
func logRequest(d *duoInterface, mintime int, path string) ([]emitEvent, error) {
	mintimes := strconv.Itoa(mintime)

	if debug == debugGCP {
		// GCP debug, make an ad-hoc GET request to test outbound
		// connectivity and then just return a test event
		log.Info("making ad-hoc request")
		resp, err := http.Get("https://www.mozilla.org")
		if err != nil {
			return nil, err
		}
		log.Infof("ad-hoc request returned status code %v\n", resp.StatusCode)
		resp.Body.Close()
		return []emitEvent{
			{"/gcp/test", map[string]interface{}{
				"gcp":       "test",
				"timestamp": time.Now().Unix(),
			}},
		}, nil
	}

	req, err := http.NewRequest("GET", "https://"+d.apiHost+path, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("mintime", mintimes)
	req.URL.RawQuery = q.Encode()

	authhdr, datehdr := d.getAuthHeader("GET", path, map[string]string{"mintime": mintimes})
	req.Header.Set("Authorization", authhdr)
	req.Header.Set("Date", datehdr)

	b, err := sendLogRequest(req)
	if err != nil {
		return nil, err
	}

	var l logRecords
	err = json.Unmarshal(b, &l)
	if err != nil {
		return nil, err
	}
	if l.Stat != "OK" {
		return nil, fmt.Errorf("%v invalid stat, got %v", path, l.Stat)
	}
	ret := make([]emitEvent, 0)
	for _, v := range l.Response {
		ret = append(ret, emitEvent{Path: path, Event: v})
	}

	return ret, nil
}

// authV2Request makes a request for auth v2 logs using both a mintime and a maxtime.
func authV2Request(d *duoInterface, mintime int, path string) ([]emitEvent, error) {
	mintimes := strconv.Itoa(mintime * 1000)
	// Set "maxtime" as a minute from now in milliseconds since epoch.
	maxtime := fmt.Sprintf("%d", time.Now().Add(time.Minute).UnixNano()/int64(time.Millisecond))

	if debug == debugGCP {
		// GCP debug, make an ad-hoc GET request to test outbound
		// connectivity and then just return a test event
		log.Info("making ad-hoc request")
		resp, err := http.Get("https://www.mozilla.org")
		if err != nil {
			return nil, err
		}
		log.Infof("ad-hoc request returned status code %v\n", resp.StatusCode)
		resp.Body.Close()
		return []emitEvent{
			{"/gcp/test", map[string]interface{}{
				"gcp":       "test",
				"timestamp": time.Now().Unix(),
			}},
		}, nil
	}

	req, err := http.NewRequest("GET", "https://"+d.apiHost+path, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("mintime", mintimes)
	q.Add("maxtime", maxtime)
	req.URL.RawQuery = q.Encode()

	authhdr, datehdr := d.getAuthHeader("GET", path, map[string]string{"mintime": mintimes, "maxtime": maxtime})
	req.Header.Set("Authorization", authhdr)
	req.Header.Set("Date", datehdr)

	b, err := sendLogRequest(req)
	if err != nil {
		return nil, err
	}

	var l authV2Records
	err = json.Unmarshal(b, &l)
	if err != nil {
		return nil, err
	}
	if l.Stat != "OK" {
		return nil, fmt.Errorf("%v invalid stat, got %v", path, l.Stat)
	}
	ret := make([]emitEvent, 0)
	for _, v := range l.Response.Authlogs {
		ret = append(ret, emitEvent{Path: path, Event: v})
	}

	return ret, nil
}

// logRequestAuth returns all authentication logs from the Duo API from mintime onwards
func logRequestAuth(d *duoInterface, mintime int) ([]emitEvent, error) {
	return authV2Request(d, mintime, AUTH_ENDPOINT)
}

// logRequestAdmin returns all administrator logs from the Duo API from mintime onwards
func logRequestAdmin(d *duoInterface, mintime int) ([]emitEvent, error) {
	return logRequest(d, mintime, ADMIN_ENDPOINT)
}

// logRequestTele returns all telephony logs from the Duo API from mintime onwards
func logRequestTele(d *duoInterface, mintime int) ([]emitEvent, error) {
	return logRequest(d, mintime, TELEPHONY_ENDPOINT)
}

// PubSubMessage is used for the function signature of the main function (Duopull())
// represent the data sent from PubSub. The data is not actually read, this is only
// used as a mechanism for triggering the function (using Cloud Scheduler or similiar)
type PubSubMessage struct {
	Data []byte `json:"data"`
}

func Duopull(ctx context.Context, psmsg PubSubMessage) error {
	var (
		m    minTime
		emit emitter
		err  error
	)

	log.Info("loading mintime state")
	err = m.load(ctx)
	if err != nil {
		log.Errorf("Error loading mintime state: %s", err)
		return err
	}

	// Define a helper function for extraction of the maximum timestamp from a
	// set of events returned from the API. If we get valid data back for a given
	// event type, the state will be adjusted so the next query starts from that
	// maximum event time + 1.
	//
	// See also https://duo.com/docs/adminapi#authentication-logs
	fh := func(es []emitEvent) (int, error) {
		var max int
		for _, x := range es {
			ts, err := x.getTimestamp()
			if err != nil {
				return 0, err
			}
			if ts > max {
				max = ts
			}
		}
		return max, nil
	}

	// Request administrator logs and adjust mintime
	log.Infof("requesting admin logs from %v\n", m.Administrator)
	e, err := logRequestAdmin(cfg.duo, m.Administrator)
	if err != nil {
		log.Errorf("Error requesting admin logs: %s", err)
		return err
	}
	nm, err := fh(e)
	if err != nil {
		log.Errorf("Error extracting timestamp from admin logs: %s", err)
		return err
	}
	if nm != 0 {
		m.Administrator = nm + 1
	}
	emit.events = append(emit.events, e...)

	// Request authentication logs and adjust mintime
	log.Infof("requesting authentication logs from %v\n", m.Authentication)
	e, err = logRequestAuth(cfg.duo, m.Authentication)
	if err != nil {
		log.Errorf("Error requesting auth logs: %s", err)
		return err
	}
	nm, err = fh(e)
	if err != nil {
		log.Errorf("Error extracting timestamp from auth logs: %s", err)
		return err
	}
	if nm != 0 {
		m.Authentication = nm + 1
	}
	emit.events = append(emit.events, e...)

	// Request telephony logs and adjust mintime
	log.Infof("requesting telephony logs from %v\n", m.Telephony)
	e, err = logRequestTele(cfg.duo, m.Telephony)
	if err != nil {
		log.Errorf("Error requesting telephony logs: %s", err)
		return err
	}
	nm, err = fh(e)
	if err != nil {
		log.Errorf("Error extracting timestamp from telephony logs: %s", err)
		return err
	}
	if nm != 0 {
		m.Telephony = nm + 1
	}
	emit.events = append(emit.events, e...)

	log.Info("writing events")
	err = emit.emit()
	if err != nil {
		log.Errorf("Error writing events: %s", err)
		return err
	}

	log.Info("saving mintime state")
	err = m.save(ctx)
	if err != nil {
		log.Errorf("Error saving mintime: %s", err)
		return err
	}

	return nil
}
