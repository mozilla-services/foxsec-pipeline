package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

type BugzillaConfig struct {
	ApiKey            string                         `yaml:"api_key"`
	AlertConfigs      map[string]BugzillaAlertConfig `yaml:"alert_configs"`
	Product           string                         `yaml:"product"`
	Component         string                         `yaml:"component"`
	Groups            []string                       `yaml:"groups"`
	DefaultAssignedTo string                         `yaml:"default_assigned_to"`
}

type BugzillaAlertConfig struct {
	TrackerBugId string `yaml:"tracker_bug_id"`
}

type BugzillaClient struct {
	Config BugzillaConfig
	Url    string
}

func NewBugzillaClient(c BugzillaConfig, url string) *BugzillaClient {
	return &BugzillaClient{c, url}
}

type CreateBug struct {
	Product     string   `json:"product"`
	Version     string   `json:"version"`
	Component   string   `json:"component"`
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	AssignedTo  string   `json:"assigned_to"`
	Blocks      string   `json:"blocks"`
	Type        string   `json:"type"`
	Groups      []string `json:"groups"`
	IsMarkdown  bool     `json:"is_markdown"`
	ApiKey      string   `json:"api_key"`
	Whiteboard  string   `json:"whiteboard"`
}

func (bc *BugzillaClient) CreateBugFromAlerts(assignedTo, category string, alerts []*Alert) (int, error) {
	summary := fmt.Sprintf("%s alerts for %s", category, time.Now().Format("2012-11-01"))

	bugText := fmt.Sprintf("## %s alerts\n---\n", category)
	for _, alert := range alerts {
		bugText = bugText + fmt.Sprintf("%s\n---\n", alert.PrettyPrint())
	}

	bugJson, err := json.Marshal(&CreateBug{
		bc.Config.Product,
		"unspecified",
		bc.Config.Component,
		summary,
		bugText,
		assignedTo,
		bc.Config.AlertConfigs[category].TrackerBugId,
		"task",
		bc.Config.Groups,
		true,
		bc.Config.ApiKey,
		category,
	})
	if err != nil {
		return 0, err
	}

	resp, err := http.Post(fmt.Sprintf("%s/rest/bug", bc.Url), "application/json", bytes.NewReader(bugJson))
	if err != nil {
		log.Errorf("Error sending request to bugzilla: %s", err)
		return 0, err
	}

	bugResp := struct {
		Id int `json:"id"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&bugResp)
	if err != nil {
		return 0, err
	}
	return bugResp.Id, nil
}

type CreateComment struct {
	Comment    string `json:"comment"`
	IsMarkdown bool   `json:"is_markdown"`
	ApiKey     string `json:"api_key"`
}

func (bc *BugzillaClient) AddAlertsToBug(bugId int, alerts []*Alert) error {
	text := "## New Alerts\n---\n"
	for _, alert := range alerts {
		text = text + fmt.Sprintf("%s\n---\n", alert.PrettyPrint())
	}
	commentJson, err := json.Marshal(&CreateComment{text, true, bc.Config.ApiKey})
	if err != nil {
		return err
	}
	resp, err := http.Post(
		fmt.Sprintf("%s/rest/bug/%d/comment", bc.Url, bugId),
		"application/json",
		bytes.NewReader(commentJson),
	)
	if err != nil {
		log.Errorf("Error sending request to bugzilla: Resp: %v | Err: %s", resp, err)
		return err
	}
	return nil
}

type SearchBug struct {
	ApiKey     string
	Creator    string
	Whiteboard string
}

// This is only a very small subset of what is returned by Bugzilla.
// Feel free to add new values as needed. Full response example can be seen here:
//	 https://bugzilla.readthedocs.io/en/latest/api/core/v1/bug.html#rest-single-bug
type SearchBugResponse struct {
	Bugs []BugResp `json:"bugs"`
}

func (sr SearchBugResponse) Len() int {
	return len(sr.Bugs)
}

func (sr SearchBugResponse) Swap(i, j int) {
	sr.Bugs[i], sr.Bugs[j] = sr.Bugs[j], sr.Bugs[i]
}

func (sr SearchBugResponse) Less(i, j int) bool {
	return sr.Bugs[i].CreationTime.Before(sr.Bugs[j].CreationTime)
}

type BugResp struct {
	Id           int       `json:"id"`
	CreationTime time.Time `json:"creation_time"`
	AssignedTo   string    `json:"assigned_to"`
}

func (bc *BugzillaClient) SearchBugs(searchValues url.Values) (*SearchBugResponse, error) {
	searchValues.Add("api_key", bc.Config.ApiKey)
	resp, err := http.Get(fmt.Sprintf("%s/rest/bug?%s", bc.Url, searchValues.Encode()))
	if err != nil {
		return nil, err
	}
	searchResp := &SearchBugResponse{}
	err = json.NewDecoder(resp.Body).Decode(&searchResp)
	if err != nil {
		return nil, err
	}
	return searchResp, nil
}
