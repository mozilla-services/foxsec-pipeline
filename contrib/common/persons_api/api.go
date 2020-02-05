package persons_api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
)

type Client struct {
	clientId     string
	clientSecret string
	accessToken  string
	httpClient   *http.Client
	baseUrl      string
	authUrl      string

	rwLock *sync.RWMutex
}

func NewClient(id, secret, baseUrl, authUrl string) (*Client, error) {
	httpClient := &http.Client{}
	c := &Client{
		httpClient:   httpClient,
		clientId:     id,
		clientSecret: secret,
		baseUrl:      baseUrl,
		authUrl:      authUrl,
		rwLock:       &sync.RWMutex{},
	}
	err := c.RefreshAccessToken()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) RefreshAccessToken() error {
	c.rwLock.Lock()
	defer c.rwLock.Unlock()
	accessToken, err := c.GetAccessToken(c.authUrl)
	if err != nil {
		return err
	}
	c.accessToken = accessToken
	return nil
}

func (c *Client) GetAccessToken(authUrl string) (string, error) {
	authReqBody, err := json.Marshal(AuthReq{
		Audience:     "api.sso.mozilla.com",
		Scope:        "classification:public display:public",
		GrantType:    "client_credentials",
		ClientId:     c.clientId,
		ClientSecret: c.clientSecret})
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Post(authUrl, "application/json", bytes.NewBuffer(authReqBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var authResp AuthResp
	err = json.Unmarshal(body, &authResp)
	if err != nil {
		return "", err
	}

	return authResp.AccessToken, nil
}

func (c *Client) GetPersonByEmail(primaryEmail string) (*Person, error) {
	c.rwLock.RLock()
	defer c.rwLock.RUnlock()
	req, err := http.NewRequest("GET", c.baseUrl+"/v2/user/primary_email/"+primaryEmail, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+c.accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Persons API responded with status code %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	p, err := UnmarshalPerson(body)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

type AuthReq struct {
	Audience     string `json:"audience"`
	Scope        string `json:"scope"`
	GrantType    string `json:"grant_type"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AuthResp struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}
