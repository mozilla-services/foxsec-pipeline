package common

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/mozilla-services/yaml"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"

	"cloud.google.com/go/storage"

	"github.com/pkg/errors"
)

// Configuration is a generic config structure for lambda functions and
// cloudfunctions. The LoadFrom function will load a yaml file in from
// either a local file or from GCS. If it is encrypted with sops, it will
// decrypt it.
type Configuration struct {
	AwsAccessKeyId     string `yaml:"aws_access_key_id"`
	AwsSecretAccessKey string `yaml:"aws_secret_access_key"`
	AwsRegion          string `yaml:"aws_region"`

	SesSenderEmail         string        `yaml:"ses_sender_email"`
	DefaultEscalationEmail string        `yaml:"default_escalation_email"`
	AlertEscalationTTL     time.Duration `yaml:"alert_escalation_ttl"`
	EmergencyCcEmail       string        `yaml:"emergency_cc_email"`

	SlackAuthToken string `yaml:"slack_auth_token"`
	SlackChannelId string `yaml:"slack_channel_id"`

	PersonsClientId     string   `yaml:"persons_client_id"`
	PersonsClientSecret string   `yaml:"persons_client_secret"`
	PersonsBaseURL      string   `yaml:"persons_base_url"`
	PersonsAuth0URL     string   `yaml:"persons_auth0_url"`
	AllowedLDAPGroups   []string `yaml:"allowed_ldap_groups"`

	IprepdInstances []IprepdInstance `yaml:"iprepd_instances"`

	Auth0Domain       string `yaml:"auth0_domain"`
	Auth0ClientId     string `yaml:"auth0_client_id"`
	Auth0ClientSecret string `yaml:"auth0_client_secret"`

	PagerdutyAuthToken            string `yaml:"pagerduty_auth_token"`
	PagerdutyTicketDutyScheduleId string `yaml:"pagerduty_ticket_duty_schedule_id"`

	BugzillaConfig BugzillaConfig `yaml:"bugzilla_config"`
}

type IprepdInstance struct {
	URL    string `yaml:"url"`
	APIKey string `yaml:"api_key"`
}

func (c *Configuration) LoadFrom(path string) error {
	var (
		confData []byte
		data     []byte
		err      error
	)
	if strings.HasPrefix(path, "gcs://") {
		data, err = getFromGCS(path)
	} else {
		data, err = ioutil.ReadFile(path)
	}
	if err != nil {
		return err
	}
	// Try to decrypt the conf using sops or load it as plaintext.
	// If the configuration is not encrypted with sops, the error
	// sops.MetadataNotFound will be returned, in which case we
	// ignore it and continue loading the conf.
	confData, err = decrypt.Data(data, "yaml")
	if err != nil {
		if err == sops.MetadataNotFound {
			// not an encrypted file
			confData = data
		} else {
			return errors.Wrap(err, "failed to load sops encrypted configuration")
		}
	}
	err = yaml.Unmarshal(confData, &c)
	if err != nil {
		return err
	}
	return nil
}

// getFromGCS will transform a string like "gcs://bucket/path/file.yaml"
// into a GCS get object call and return the contents of file.yaml.
func getFromGCS(path string) ([]byte, error) {
	if !strings.HasPrefix(path, "gcs://") {
		return nil, errors.New(fmt.Sprintf("%s is not a gcs url", path))
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	split := strings.Split(strings.Split(path, "gcs://")[1], "/")
	bucketName := split[0]
	filePath := strings.Join(split[1:], "/")

	r, err := client.Bucket(bucketName).Object(filePath).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return data, nil
}
