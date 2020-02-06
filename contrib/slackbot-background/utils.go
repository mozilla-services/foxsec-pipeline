package slackbotbackground

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
)

var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
var ROUGHLY_TEN_YEARS_FROM_NOW = time.Hour * 24 * 30 * 12 * 10

func isEmailValid(email string) error {
	if len(email) > 254 || !rxEmail.MatchString(email) {
		return fmt.Errorf("Email (%s) is invalid", email)
	}
	return nil
}

func checkUsersGroups(email string) (bool, error) {
	err := isEmailValid(email)
	if err != nil {
		return false, err
	}

	person, err := globals.personsClient.GetPersonByEmail(email)
	if err != nil {
		return false, err
	}

	groups := []string{}
	for group := range person.AccessInformation.LDAP.Values {
		groups = append(groups, group)
		for _, allowedGroup := range config.AllowedLDAPGroups {
			if group == allowedGroup {
				log.Infof("%s has allowed ldap group: %s", email, group)
				return true, nil
			}
		}
	}

	log.Infof("%s's groups (%v) do not include an allowed ldap group (%v)", email, groups, config.AllowedLDAPGroups)

	return false, nil
}

func parseWhitelistText(text, typestr string) (string, time.Time, string, error) {
	splitCmd := strings.Split(text, " ")

	obj := splitCmd[0]
	var err error
	if typestr == common.EMAIL_TYPE {
		err = isEmailValid(obj)
	} else if typestr == common.IP_TYPE {
		ip := net.ParseIP(obj)
		if ip == nil {
			err = fmt.Errorf("Got invalid IP: %s", obj)
		} else {
			obj = ip.String()
		}
	} else {
		err = fmt.Errorf("Invalid type")
	}

	if err != nil {
		m := fmt.Sprintf("Got invalid %s: %s", typestr, obj)
		errMsg := m
		return "", time.Time{}, errMsg, err
	}

	expiresAt, err := parseExpires(splitCmd)
	if err != nil {
		log.Errorf("Error parsing duration: %s", err)
		errMsg := fmt.Sprintf("Was unable to parse duration: %s\n%s", splitCmd[1], DURATION_DOC)
		return "", time.Time{}, errMsg, err
	}

	return obj, expiresAt, "", nil
}

func parseExpires(splitText []string) (time.Time, error) {
	var expiresDur time.Duration
	var err error
	if len(splitText) == 2 {
		if splitText[1] == "never" {
			expiresDur = ROUGHLY_TEN_YEARS_FROM_NOW
		} else {
			expiresDur, err = time.ParseDuration(splitText[1])
			if err != nil {
				return time.Time{}, err
			}
			// Clamp expires duration to >5 minutes
			if expiresDur < time.Minute*5 {
				expiresDur = time.Minute * 5
			}
		}
	} else {
		expiresDur = DEFAULT_EXPIRATION_DURATION
	}

	return time.Now().Add(expiresDur), nil
}

func sendSlackCallback(msg *slack.Msg, responseUrl string) error {
	j, err := json.Marshal(msg)
	if err != nil {
		log.Errorf("Error marshalling slack message: %s", err)
		return err
	}
	resp, err := client.Post(responseUrl, "application/json", bytes.NewBuffer(j))
	if err != nil {
		log.Errorf("Error sending slack callback: %s", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		log.Errorf("Received response to slack callback with code %d", resp.StatusCode)
		return errors.New(fmt.Sprintf("Slack callback with response %d", resp.StatusCode))
	}
	return nil
}

func isAlertConfirm(callbackId string) bool {
	return strings.HasPrefix(callbackId, "alert_confirmation")
}

func deleteObjFromIprepd(obj, typestr string) error {
	client := http.Client{Timeout: time.Second * 10}
	for _, iprepdInstance := range config.IprepdInstances {
		log.Infof("Sending DELETE request to %s for %s/%s", iprepdInstance.URL, typestr, obj)

		req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/type/%s/%s", iprepdInstance.URL, typestr, obj), nil)
		if err != nil {
			return err
		}
		req.Header.Add("Authorization", "APIKey "+iprepdInstance.APIKey)
		resp, err := client.Do(req)
		if err != nil {
			log.Errorf("Error send request to %s: %s", iprepdInstance.URL, err)
		}
		if resp.StatusCode > 299 {
			log.Errorf("Got response with status code %d from %s", resp.StatusCode, iprepdInstance.URL)
		}
	}
	return nil
}

func getCallerDetails(userid string) string {
	userProfile, err := globals.slackClient.GetUserProfile(userid, false)
	if err != nil {
		log.Errorf("Unable to find slack user with id %s", userid)
		return "unknown user"
	}
	return fmt.Sprintf("%s (%s)", userProfile.RealNameNormalized, userProfile.Email)
}
