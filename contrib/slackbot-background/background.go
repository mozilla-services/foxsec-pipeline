package slackbotbackground

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"
	"github.com/mozilla-services/foxsec-pipeline/contrib/common/persons_api"

	"cloud.google.com/go/pubsub"
	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

const (
	UNBLOCK_IP_SLASH_COMMAND            = "/unblock_ip"
	STAGING_UNBLOCK_IP_SLASH_COMMAND    = "/staging_unblock_ip"
	UNBLOCK_EMAIL_SLASH_COMMAND         = "/unblock_email"
	STAGING_UNBLOCK_EMAIL_SLASH_COMMAND = "/staging_unblock_email"

	CHECK_IP_SLASH_COMMAND            = "/check_ip"
	STAGING_CHECK_IP_SLASH_COMMAND    = "/staging_check_ip"
	CHECK_EMAIL_SLASH_COMMAND         = "/check_email"
	STAGING_CHECK_EMAIL_SLASH_COMMAND = "/staging_check_email"

	SECOPS_911_COMMAND         = "/secops911"
	STAGING_SECOPS_911_COMMAND = "/staging_secops911"

	DEFAULT_EXPIRATION_DURATION = time.Hour * 24
	DURATION_DOC                = "FoxsecBot uses Go's time.ParseDuration internally " +
		"with some custom checks. Examples: '72h' or '2h45m'. " +
		"Valid time units are 'm' and 'h'. If you omit a duration, " +
		"the default (24 hours) is used. If your duration is under " +
		"5 minutes, it is increased to 5 minutes. If you do not want the " +
		"exempted IP to expire, put 'never' as the expiration. This " +
		"will make the expiration duration roughly ten years from now."

	FOURTEEN_DAYS_AGO = time.Hour * 24 * 14
)

var (
	globals Globals
	client  *http.Client
	DB      *common.DBClient

	config = &common.Configuration{}

	ALLOWED_COMMANDS = []string{
		UNBLOCK_IP_SLASH_COMMAND,
		STAGING_UNBLOCK_IP_SLASH_COMMAND,
		UNBLOCK_EMAIL_SLASH_COMMAND,
		STAGING_UNBLOCK_EMAIL_SLASH_COMMAND,
		SECOPS_911_COMMAND,
		STAGING_SECOPS_911_COMMAND,
		CHECK_IP_SLASH_COMMAND,
		CHECK_EMAIL_SLASH_COMMAND,
		STAGING_CHECK_IP_SLASH_COMMAND,
		STAGING_CHECK_EMAIL_SLASH_COMMAND,
	}

	// dirty hack to disable init in unit tests
	_testing = false
)

func init() {
	mozlogrus.Enable("slackbot-background")
	if _testing {
		return
	}
	client = &http.Client{
		Timeout: 10 * time.Second,
	}
	InitConfig()

	PROJECT_ID := os.Getenv("GCP_PROJECT")
	var err error
	DB, err = common.NewDBClient(context.Background(), PROJECT_ID)
	if err != nil {
		log.Errorf("Error creating db client: %s", err)
		return
	}
}

type Globals struct {
	slackClient   *slack.Client
	personsClient persons_api.PersonsClient
	sesClient     common.EscalationMailer
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

	globals.sesClient, err = common.NewSESClientFromConfig(config)
	if err != nil {
		log.Fatalf("Could not setup SESClient. Err: %s", err)
	}

	globals.slackClient = slack.New(config.SlackAuthToken)

	globals.personsClient, err = persons_api.NewClient(
		config.PersonsClientId,
		config.PersonsClientSecret,
		config.PersonsBaseURL,
		config.PersonsAuth0URL,
	)
	if err != nil {
		log.Fatalf("Could not create persons api client: %s", err)
	}

	go func() {
		for {
			time.Sleep(time.Hour)
			log.Info("Refreshing access token")
			err = globals.personsClient.RefreshAccessToken()
			if err != nil {
				log.Errorf("Error refreshing persons access token: %s", err)
			}
		}
	}()

	log.Infof("Allowed LDAP Groups for Exempt Command: %v", config.AllowedLDAPGroups)
}

func allowedCommand(cmd string) bool {
	for _, allowedCmd := range ALLOWED_COMMANDS {
		if allowedCmd == cmd {
			return true
		}
	}
	return false
}

func alertEscalator(ctx context.Context) error {
	alerts, err := DB.GetAllAlerts(ctx)
	if err != nil {
		log.Errorf("Error getting all alerts: %s", err)
		return err
	}

	for _, alert := range alerts {
		log.Infof("Checking alert %s", alert.Id)
		if alert.IsStatus(common.ALERT_NEW) && alert.OlderThan(config.AlertEscalationTTL) {
			log.Infof("Escalating alert %s", alert.Id)
			alert.SetMetadata(common.META_STATUS, common.ALERT_ESCALATED)

			// TODO: If we retry based off an error here, we could
			//		   potentially send an escalation email multiple times.
			err := globals.sesClient.SendEscalationEmail(alert)
			if err != nil {
				log.Errorf("Error escalating alert (%s). Err: %s", alert.Id, err)
				return err
			}
			err = DB.SaveAlert(ctx, alert)
			if err != nil {
				log.Errorf("Error updating alert as escalated (%s). Err: %s", alert.Id, err)
				return err
			}
		}
	}

	return nil
}

func SlackbotBackground(ctx context.Context, psmsg pubsub.Message) error {
	var (
		resp *slack.Msg
		err  error
	)
	td, err := common.PubSubMessageToTriggerData(psmsg)
	if err != nil {
		log.Errorf("Error decoding pubsub message: %s", err)
		return nil
	}

	if td.Action == common.SlashCommand {
		log.Infof("Got slash command: %s", td.SlashCommand.Cmd)
		switch td.SlashCommand.Cmd {
		case SECOPS_911_COMMAND, STAGING_SECOPS_911_COMMAND:
			resp, err = handle911Cmd(ctx, td.SlashCommand, DB)
		case CHECK_EMAIL_SLASH_COMMAND, CHECK_IP_SLASH_COMMAND, STAGING_CHECK_EMAIL_SLASH_COMMAND, STAGING_CHECK_IP_SLASH_COMMAND:
			resp, err = handleCheckCmd(ctx, td.SlashCommand, client)
		case UNBLOCK_EMAIL_SLASH_COMMAND, UNBLOCK_IP_SLASH_COMMAND, STAGING_UNBLOCK_EMAIL_SLASH_COMMAND, STAGING_UNBLOCK_IP_SLASH_COMMAND:
			resp, err = handleUnblockCmd(ctx, td.SlashCommand, DB)
		default:
			resp, err = nil, errors.New("Unsupported slash command")
		}
		if err != nil {
			log.Errorf("error handling %s command: %s", td.SlashCommand.Cmd, err)
			return err
		}
		if resp != nil {
			log.Infof("Sending response: %s", resp.Text)
			err = sendSlackCallback(resp, td.SlashCommand.ResponseURL)
			if err != nil {
				log.Errorf("error sending slack callback within slash command: %s", err)
				return err
			}
		}
	} else if td.Action == common.Interaction {
		log.Info("Got interaction action trigger")
		if isAlertConfirm(td.Interaction.CallbackID) {
			resp, err := handleAlertConfirm(ctx, td.Interaction, DB)
			if err != nil {
				log.Errorf("Error handling alert confirmation interaction: %s", err)
			}
			if resp != nil {
				err = sendSlackCallback(resp, td.Interaction.ResponseURL)
				if err != nil {
					log.Errorf("error sending slack callback for interaction: %s", err)
					return err
				}
			}
		}
	} else if td.Action == common.ScheduledTask {
		log.Info("Got scheduled task action trigger")
		// We don't want to return an error here, as we don't need the
		// pubsub/cloudfunction retry mechanism to retry these, as they are scheduled tasks.
		err = alertEscalator(ctx)
		if err != nil {
			log.Errorf("Error escalating alerts: %s", err)
		}
		err = DB.RemoveExpiredExemptedObjects(ctx)
		if err != nil {
			log.Errorf("Error purging expired exempted ips: %s", err)
		}
		err = DB.RemoveAlertsOlderThan(ctx, FOURTEEN_DAYS_AGO)
		if err != nil {
			log.Errorf("Error removing old alerts: %s", err)
		}
	}

	return nil
}
