package com.mozilla.secops.alert;

import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.SlackApiResponse;
import com.mozilla.secops.crypto.RuntimeSecrets;
import com.mozilla.secops.slack.SlackManager;
import java.io.IOException;
import java.util.HashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AlertSlack {
  private final AlertConfiguration cfg;
  private SlackManager slackManager;
  private HashMap<String, String> emailToSlackUserId;
  private final Logger log;

  /** Construct new alert slack object */
  public AlertSlack(AlertConfiguration cfg) {
    log = LoggerFactory.getLogger(AlertSlack.class);
    try {
      String slackToken = RuntimeSecrets.interpretSecret(cfg.getSlackToken(), cfg.getGcpProject());
      slackManager = new SlackManager(slackToken);
    } catch (IOException exc) {
      log.error("failed to get slack token: {}", exc.getMessage());
    }
    this.cfg = cfg;
  }

  /**
   * Send alert to slack catchall channel
   *
   * @param a Alert
   * @return Boolean on whether the alert was sent successfully
   */
  public Boolean sendToCatchall(Alert a) {
    log.info("generating catchall slack for {} (channel id)", cfg.getSlackCatchall());

    String text = String.format("%s (%s)", a.getSummary(), a.getAlertId());
    try {
      return handleSlackResponse(slackManager.sendMessageToChannel(cfg.getSlackCatchall(), text));
    } catch (IOException exc) {
      log.error("error sending slack alert (IOException): {}", exc.getMessage());
    } catch (SlackApiException exc) {
      log.error("error sending slack alert (SlackApiException): {}", exc.getMessage());
    }
    return false;
  }

  /**
   * Send an alert to a user asking them if it was caused by them. Used for AuthProfile
   *
   * @param a Alert
   * @param userId Slack user id
   * @return Boolean on whether the alert was sent successfully
   */
  public Boolean confirmationAlert(Alert a, String userId) {
    if (a == null || userId == null) {
      return false;
    }

    log.info("generating slack message for {}", userId);

    String text =
        String.format(
            "Foxsec Fraud Detection Alert\n\n%s\n%s\nAlert Id: %s",
            a.getSummary(), a.assemblePayload(), a.getAlertId());
    try {
      return handleSlackResponse(
          slackManager.sendConfirmationRequestToUser(userId, a.getAlertId().toString(), text));
    } catch (IOException exc) {
      log.error("error sending slack alert (IOException): {}", exc.getMessage());
    } catch (SlackApiException exc) {
      log.error("error sending slack alert (SlackApiException): {}", exc.getMessage());
    }
    return false;
  }

  /**
   * Get slack user id from user's email
   *
   * @param email User's email
   * @return User's slack user id
   */
  public String getUserId(String email) {
    if (emailToSlackUserId == null) {
      // TODO: Move this to IdentityManager
      try {
        emailToSlackUserId = slackManager.getEmailToUserIdMapping();
      } catch (IOException exc) {
        log.error("error getting user list from slack (IOException): {}", exc.getMessage());
      } catch (SlackApiException exc) {
        log.error("error getting user list from slack (SlackApiException): {}", exc.getMessage());
      }

      emailToSlackUserId = null;
      return null;
    }
    return emailToSlackUserId.get(email);
  }

  private Boolean handleSlackResponse(SlackApiResponse resp) {
    if (resp.isOk()) {
      return true;
    }
    if (resp.getError() != null && resp.getError() != "") {
      log.error("error sending slack alert: {}", resp.getError());
    }
    if (resp.getWarning() != null && resp.getWarning() != "") {
      log.warn("warning from sending slack alert: {}", resp.getWarning());
    }
    return false;
  }
}
