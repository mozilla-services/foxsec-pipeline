package slackbotbackground

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline/contrib/common"

	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
)

// sends an email to the escalation address
func handle911Cmd(ctx context.Context, cmd common.SlashCommandData, db *common.DBClient) (*slack.Msg, error) {
	msg := &slack.Msg{}
	log.Infof("User %s invoked secops911 with message: %s", cmd.UserID, cmd.Text)
	caller := getCallerDetails(cmd.UserID)
	err := globals.sesClient.Send911Email(caller, config.EmergencyCcEmail, cmd.Text)
	if err != nil {
		msg.Text = fmt.Sprintf("Unable contact on call. Please directly email %s", globals.sesClient.DefaultEscalationEmail())
		return msg, err
	}
	msg.Text = "SecOps on call has been paged. Hold on and don't panic!"
	return msg, nil
}

func handleUnblockCmd(ctx context.Context, cmd common.SlashCommandData, db *common.DBClient) (*slack.Msg, error) {
	var (
		err    error
		errMsg string
	)
	msg := &slack.Msg{}
	exemptedObject := &common.ExemptedObject{}

	if cmd.Cmd == UNBLOCK_IP_SLASH_COMMAND || cmd.Cmd == STAGING_UNBLOCK_IP_SLASH_COMMAND {
		exemptedObject.Type = common.IP_TYPE
	} else if cmd.Cmd == UNBLOCK_EMAIL_SLASH_COMMAND || cmd.Cmd == STAGING_UNBLOCK_EMAIL_SLASH_COMMAND {
		exemptedObject.Type = common.EMAIL_TYPE
	} else {
		err = fmt.Errorf("Error processing command")
		msg.Text = err.Error()
		return msg, err
	}

	exemptedObject.Object, exemptedObject.ExpiresAt, errMsg, err = parseExemptText(cmd.Text, exemptedObject.Type)
	if err != nil {
		msg.Text = errMsg
		return msg, err
	}

	userProfile, err := globals.slackClient.GetUserProfile(cmd.UserID, false)
	if err != nil {
		log.Errorf("Error getting user profile: %s", err)
		msg.Text = "Was unable to get your email from Slack."
		return msg, err
	}

	allowed, err := checkUsersGroups(userProfile.Email)
	if err != nil {
		log.Errorf("Error with checking user's (%s) ldap groups: %s", userProfile.Email, err)
		msg.Text = "Error checking your ldap groups."
		return msg, err
	}
	if !allowed {
		err = fmt.Errorf("User (%s) is not allowed to use this slack command.", userProfile.Email)
		log.Error(err)
		msg.Text = "You are not authorized to perform that command."
		return msg, nil
	}

	exemptedObject.CreatedBy = userProfile.Email
	auditMsg := fmt.Sprintf("%s submitted %s to be exempt from iprepd reporting until %s", userProfile.Email, exemptedObject.Object, exemptedObject.ExpiresAt.Format(time.UnixDate))
	log.Info(auditMsg)
	err = db.SaveExemptedObject(ctx, exemptedObject)
	if err != nil {
		log.Errorf("Error saving exempted object: %s", err)
		msg.Text = "Error saving exemption."
		return msg, err
	}

	err = deleteObjFromIprepd(exemptedObject.Object, exemptedObject.Type)
	if err != nil {
		log.Errorf("Error deleting %s from iprepd: %s", exemptedObject.Object, err)
	}

	// send to audit channel
	_, _, err = globals.slackClient.PostMessage(config.SlackChannelId, slack.MsgOptionText(auditMsg, false))
	if err != nil {
		log.Errorf("Error sending audit message to foxsec bot slack channel: %s", err)
	}

	msg.Text = fmt.Sprintf("Successfully saved %s to the exemptions list. Will expire at %s", exemptedObject.Object, exemptedObject.ExpiresAt.Format(time.UnixDate))
	return msg, nil
}

func handleCheckCmd(ctx context.Context, cmd common.SlashCommandData, client *http.Client) (*slack.Msg, error) {
	var (
		err         error
		errMsg      string
		objectType  string
		objectValue string
	)
	msg := &slack.Msg{}

	if cmd.Cmd == CHECK_IP_SLASH_COMMAND || cmd.Cmd == STAGING_CHECK_IP_SLASH_COMMAND {
		objectType = common.IP_TYPE
	} else if cmd.Cmd == CHECK_EMAIL_SLASH_COMMAND || cmd.Cmd == STAGING_CHECK_EMAIL_SLASH_COMMAND {
		objectType = common.EMAIL_TYPE
	} else {
		err = fmt.Errorf("Error processing command")
		msg.Text = err.Error()
		return msg, err
	}

	if err != nil {
		msg.Text = errMsg
		return msg, err
	}

	userProfile, err := globals.slackClient.GetUserProfile(cmd.UserID, false)
	if err != nil {
		log.Errorf("Error getting user profile: %s", err)
		msg.Text = "Was unable to get your email from Slack."
		return msg, err
	}

	allowed, err := checkUsersGroups(userProfile.Email)
	if err != nil {
		log.Errorf("Error with checking user's (%s) ldap groups: %s", userProfile.Email, err)
		msg.Text = "Error checking your ldap groups."
		return msg, err
	}
	if !allowed {
		err = fmt.Errorf("User (%s) is not allowed to use this slack command.", userProfile.Email)
		log.Error(err)
		msg.Text = "You are not authorized to perform that command."
		return msg, nil
	}

	objectValue = cmd.Text
	log.Infof("Checking reputation for %s by %s", objectValue, userProfile.Email)

	results := checkObjFromIprepd(client, objectValue, objectType)
	msg.Text = results
	return msg, nil
}

func handleAlertConfirm(ctx context.Context, callback common.InteractionData, db *common.DBClient) (*slack.Msg, error) {
	// callback id = "alert_confirmation_<id>"
	alertId := strings.Split(callback.CallbackID, "_")[2]
	alert, err := db.GetAlert(ctx, alertId)
	if err != nil {
		log.Errorf("Could not find alert with ID %s (from Callback ID: %s). Err: %s", alertId, callback.CallbackID, err)
		return nil, err
	}

	response := &slack.Msg{
		Text:            "Error responding; please contact SecOps (secops@mozilla.com)",
		ReplaceOriginal: false,
	}

	if !alert.IsStatus(common.ALERT_NEW) {
		alertStatus := alert.GetMetadata(common.META_STATUS)
		log.Infof("Alert %s has already been marked as %s", alert.Id, alertStatus)
		response.Text = fmt.Sprintf("Thank you for responding! Alert has already been marked as %s.\nalert id: %s", alertStatus, alert.Id)
		return response, nil
	}

	if callback.ActionName == "alert_yes" {
		alert.SetMetadata(common.META_STATUS, common.ALERT_ACKNOWLEDGED)
		err := db.SaveAlert(ctx, alert)
		if err != nil {
			log.Errorf("Error marking alert (%s) as acknowledged. Err: %s", alert.Id, err)
			return response, err
		}
		log.Infof("Alert %s has been acknowledged", alert.Id)
		response.Text = fmt.Sprintf("Thank you for responding! Alert has been acknowledged.\nalert id: %s", alert.Id)
	} else if callback.ActionName == "alert_no" {
		// Override `escalate_to` to use the default (which should be the security teams main pagerduty email)
		alert.SetMetadata(common.META_ESCALATE_TO, "")
		err := globals.sesClient.SendEscalationEmail(alert)
		if err != nil {
			log.Errorf("Error escalating alert (%s). Err: %s", alert.Id, err)
			return response, err
		}
		alert.SetMetadata(common.META_STATUS, common.ALERT_ESCALATED)
		err = db.SaveAlert(ctx, alert)
		if err != nil {
			log.Errorf("Error updating alert as escalated (%s). Err: %s", alert.Id, err)
			return response, err
		}
		log.Infof("Alert %s has been escalated", alert.Id)
		response.Text = fmt.Sprintf("Thank you for responding! Alert has been escalated.\nalert id: %s", alert.Id)
	}

	return response, nil
}
