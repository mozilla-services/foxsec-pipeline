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
	PROJECT_ID   string
	pubsubClient *pubsub.Client
	config       = &common.Configuration{}

	// dirty hack to disable init in unit tests
	_testing = false
)

func init() {
	mozlogrus.Enable("slackbot-http")
	if _testing {
		return
	}
	PROJECT_ID = os.Getenv("GCP_PROJECT")
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

	pubsubClient, err = pubsub.NewClient(context.Background(), PROJECT_ID)
	if err != nil {
		log.Fatalf("Could not create pubsub client. Err: %s", err)
	}

	topic := pubsubClient.Topic(config.SlackbotTriggerTopicName)
	ok, err := topic.Exists(context.Background())
	if err != nil {
		log.Errorf("Error checking whether topic (%s) exists. Err: %s", config.SlackbotTriggerTopicName, err)
		return
	}
	if !ok {
		log.Fatalf("Topic `%s` does not exist.", config.SlackbotTriggerTopicName)
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
	sv, err := slack.NewSecretsVerifier(r.Header, config.SlackSigningSecret)
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
				ActionName:  callback.ActionCallback.AttachmentActions[0].Name,
				CallbackID:  callback.CallbackID,
				ResponseURL: callback.ResponseURL,
			},
		}
	}

	if data != nil {
		topic := pubsubClient.Topic(config.SlackbotTriggerTopicName)
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
