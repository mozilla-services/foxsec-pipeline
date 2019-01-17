package com.mozilla.secops.alert;

import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.SlackApiResponse;
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

  public AlertSlack(AlertConfiguration cfg) {
    slackManager = new SlackManager(cfg.getSlackToken());
    log = LoggerFactory.getLogger(AlertSlack.class);
    this.cfg = cfg;
  }

  public Boolean sendToCatchall(Alert a) {
    log.info("generating catchall slack for {} (channel id)", cfg.getSlackCatchall());
    String text =
        String.format(
            "Foxsec Fraud Detection Alert\n\n%s\n%s\nAlert Id: %s",
            a.getSummary(), a.assemblePayload(), a.getAlertId());

    try {
      return handleSlackResponse(slackManager.sendMessageToChannel(cfg.getSlackCatchall(), text));
    } catch (IOException exc) {
      log.error("error sending slack alert (IOException): {}", exc.getMessage());
    } catch (SlackApiException exc) {
      log.error("error sending slack alert (SlackApiException): {}", exc.getMessage());
    }
    return false;
  }

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
