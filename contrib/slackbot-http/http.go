package slackbothttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"

	"cloud.google.com/go/pubsub"
	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var (
	globalConfig Config
	KEYNAME      string
	PROJECT_ID   string
)

func init() {
	mozlogrus.Enable("slackbot-http")
	KEYNAME = os.Getenv("KMS_KEYNAME")
	PROJECT_ID = os.Getenv("GCP_PROJECT")
	InitConfig()
}

type Config struct {
	pubsubClient       *pubsub.Client
	slackSigningSecret string
	triggerTopicName   string
}

func InitConfig() {
	kms, err := common.NewKMSClient()
	if err != nil {
		log.Fatalf("Could not create kms client. Err: %s", err)
	}

	globalConfig.slackSigningSecret, err = kms.DecryptEnvVar(KEYNAME, "SLACK_SIGNING_SECRET")
	if err != nil {
		log.Fatalf("Could not decrypt slack signing secret. Err: %s", err)
	}

	globalConfig.pubsubClient, err = pubsub.NewClient(context.Background(), PROJECT_ID)
	if err != nil {
		log.Fatalf("Could not create pubsub client. Err: %s", err)
	}

	globalConfig.triggerTopicName = os.Getenv("TRIGGER_TOPIC_NAME")

	topic := globalConfig.pubsubClient.Topic(globalConfig.triggerTopicName)
	ok, err := topic.Exists(context.Background())
	if err != nil {
		log.Errorf("Error checking whether topic (%s) exists. Err: %s", globalConfig.triggerTopicName, err)
		return
	}
	if !ok {
		log.Fatalf("Topic `%s` does not exist.", globalConfig.triggerTopicName)
	}
}

func InteractionCallbackParse(reqBody []byte) (*slack.InteractionCallback, error) {
	var req slack.InteractionCallback
	// Deal with slack weirdness. Body is `payload=<escaped json>`
	jsonStr, err := url.QueryUnescape(string(reqBody)[8:])
	err = json.Unmarshal([]byte(jsonStr), &req)
	if err != nil {
		log.Errorf("Error parsing interaction callback: Body: %s | Err: %s", reqBody, err)
		return nil, err
	}
	return &req, nil
}

func verifySignature(r *http.Request) ([]byte, error) {
	// Check signature
	sv, err := slack.NewSecretsVerifier(r.Header, globalConfig.slackSigningSecret)
	if err != nil {
		log.Errorf("Error creating secrets verifier: %s", err)
		return nil, err
	}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Error reading request body: %s", err)
		return nil, err
	}
	sv.Write(buf)
	// Add body again, so that slack lib helpers (like SlashCommandParse) can be used.
	r.Body = ioutil.NopCloser(bytes.NewBuffer(buf))

	err = sv.Ensure()
	if err != nil {
		log.Errorf("Error checking signature in header: %s", err)
		return nil, err
	}

	return buf, nil
}

func SlackbotHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	body, err := verifySignature(r)
	if err != nil {
		log.Errorf("Error verifying signature: %s", err)
		return
	}

	var data *common.TriggerData
	if cmd, err := slack.SlashCommandParse(r); err == nil && cmd.Command != "" {
		log.Infof("Got slash command: %s", cmd.Command)
		data = &common.TriggerData{
			Action: common.SlashCommand,
			SlashCommand: common.SlashCommandData{
				Cmd:         cmd.Command,
				Text:        cmd.Text,
				ResponseURL: cmd.ResponseURL,
				UserID:      cmd.UserID,
			},
		}
	} else if callback, err := InteractionCallbackParse(body); err == nil {
		log.Info("Got interaction request.")
		data = &common.TriggerData{
			Action: common.Interaction,
			Interaction: common.InteractionData{
				ActionName:  callback.Actions[0].Name,
				CallbackID:  callback.CallbackID,
				ResponseURL: callback.ResponseURL,
			},
		}
	}

	if data != nil {
		topic := globalConfig.pubsubClient.Topic(globalConfig.triggerTopicName)
		defer topic.Stop()

		psmsg, err := data.ToPubSubMessage()
		if err != nil {
			log.Errorf("Error transforming trigger data to pubsub message: %s", err)
			return
		}

		topic.Publish(r.Context(), psmsg)
	}

	return
}
