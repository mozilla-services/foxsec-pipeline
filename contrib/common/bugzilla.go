package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

type BugzillaConfig struct {
	ApiKey            string            `yaml:"api_key"`
	CategoryToTracker map[string]string `yaml:"category_to_tracker"`
	Product           string            `yaml:"product"`
	Component         string            `yaml:"component"`
	Groups            []string          `yaml:"groups"`
	DefaultAssignedTo string            `yaml:"default_assigned_to"`
}

type BugzillaClient struct {
	Config BugzillaConfig
	Url    string
}

func NewBugzillaClient(c BugzillaConfig, url string) *BugzillaClient {
	return &BugzillaClient{c, url}
}

type BugzillaErrorResponse struct {
	Error   bool   `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

func (bc *BugzillaClient) CreateDefaultBugzillaRequest(method string, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Add("User-Agent", "FoxSec-Bugzilla-Alert-Manager")
	req.Header.Add("X-BUGZILLA-API-KEY", bc.Config.ApiKey)
	req.Header.Add("Accept", "application/json")
	return req, nil
}

type CreateBug struct {
	Product     string   `json:"product"`
	Version     string   `json:"version"`
	Component   string   `json:"component"`
	Summary     string   `json:"summary"`
	Alias       string   `json:"alias"`
	Description string   `json:"description"`
	AssignedTo  string   `json:"assigned_to"`
	Blocks      string   `json:"blocks"`
	Type        string   `json:"type"`
	Groups      []string `json:"groups"`
	Whiteboard  string   `json:"whiteboard"`
}

func (bc *BugzillaClient) CreateBugFromAlerts(assignedTo, category string, alerts []*Alert) (int, error) {
	n := time.Now().Format("2006-01-02")
	summary := fmt.Sprintf("%s alerts for %s", category, n)
	alias := fmt.Sprintf("foxsec-%s-%s", category, n)

	bugText := fmt.Sprintf("## %s alerts\n---\n", category)
	for _, alert := range alerts {
		bugText = bugText + fmt.Sprintf("%s\n---\n", alert.MarkdownFormat())
	}

	bugJson, err := json.Marshal(&CreateBug{
		Product:     bc.Config.Product,
		Version:     "unspecified",
		Component:   bc.Config.Component,
		Summary:     summary,
		Alias:       alias,
		Description: bugText,
		AssignedTo:  assignedTo,
		Blocks:      bc.Config.CategoryToTracker[category],
		Type:        "task",
		Groups:      bc.Config.Groups,
		Whiteboard:  category,
	})
	if err != nil {
		return 0, err
	}

	req, err := bc.CreateDefaultBugzillaRequest(http.MethodPost, fmt.Sprintf("%s/rest/bug", bc.Url), bytes.NewReader(bugJson))
	if err != nil {
		log.Errorf("Error creating request: %s", err)
		return 0, err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("Error sending request to bugzilla: %s", err)
		return 0, err
	}
	if resp.StatusCode > 299 {
		log.Errorf("Got status code of %d from create bug request %s", resp.StatusCode, string(bugJson))

		errResp := BugzillaErrorResponse{}
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return 0, err
		}
		log.Errorf("Bugzilla Error Response: Message: %s | Code: %d", errResp.Message, errResp.Code)
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
}

func (bc *BugzillaClient) AddAlertsToBug(bugId int, alerts []*Alert) error {
	text := "## New Alerts\n---\n"
	for _, alert := range alerts {
		text = text + fmt.Sprintf("%s\n---\n", alert.MarkdownFormat())
	}
	commentJson, err := json.Marshal(&CreateComment{text, true})
	if err != nil {
		return err
	}

	req, err := bc.CreateDefaultBugzillaRequest(
		http.MethodPost,
		fmt.Sprintf("%s/rest/bug/%d/comment", bc.Url, bugId),
		bytes.NewReader(commentJson),
	)
	if err != nil {
		log.Errorf("Error creating request: %s", err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("Error sending request to bugzilla: Resp: %v | Err: %s", resp, err)
		return err
	}
	return nil
}

type SearchBug struct {
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
	IsOpen       bool      `json:"is_open"`
}

func (bc *BugzillaClient) SearchBugs(searchValues url.Values) (*SearchBugResponse, error) {
	req, err := bc.CreateDefaultBugzillaRequest(
		http.MethodGet,
		fmt.Sprintf("%s/rest/bug?%s", bc.Url, searchValues.Encode()),
		nil,
	)
	if err != nil {
		log.Errorf("Error creating request: %s", err)
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
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

type UpdateBugReq struct {
	Status string `json:"status"`
}

const ASSIGNED = "ASSIGNED"

func (bc *BugzillaClient) UpdateBug(bugId int, updateReq *UpdateBugReq) error {
	updateJson, err := json.Marshal(updateReq)
	if err != nil {
		return err
	}

	req, err := bc.CreateDefaultBugzillaRequest(http.MethodPut, fmt.Sprintf("%s/rest/bug/%d", bc.Url, bugId), bytes.NewReader(updateJson))
	if err != nil {
		log.Errorf("Error creating request: %s", err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("Error sending request to bugzilla: %s", err)
		return err
	}
	if resp.StatusCode > 299 {
		log.Errorf("Got status code of %d from update bug request %s", resp.StatusCode, string(updateJson))

		errResp := BugzillaErrorResponse{}
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		if err != nil {
			return err
		}
		log.Errorf("Bugzilla Error Response: Message: %s | Code: %d", errResp.Message, errResp.Code)
		return err
	}

	return nil
}
