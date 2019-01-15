package com.mozilla.secops.alert;

import com.github.seratch.jslack.api.methods.SlackApiException;
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
    String text =
        String.format(
            "Foxsec Fraud Detection Alert\n\n%s\n%s\nAlert Id: %s",
            a.getSummary(), a.assemblePayload(), a.getAlertId());
    Boolean resp = false;
    try {
      resp = slackManager.sendMessageToChannel(cfg.getSlackCatchall(), text);
    } catch (IOException exc) {
      log.error("error sending slack alert (IOException): {}", exc.getMessage());
    } catch (SlackApiException exc) {
      log.error("error sending slack alert (SlackApiException): {}", exc.getMessage());
    }
    return resp;
  }

  public Boolean confirmationAlert(Alert a, String userId) throws IOException, SlackApiException {
    log.info("generating slack message for {}", userId);

    String text =
        String.format(
            "Foxsec Fraud Detection Alert\n\n%s\n%s\nAlert Id: %s",
            a.getSummary(), a.assemblePayload(), a.getAlertId());
    return slackManager.sendConfirmationRequestToUser(userId, a.getAlertId().toString(), text);
  }

  public String getUserId(String email) throws IOException, SlackApiException {
    if (emailToSlackUserId == null) {
      // TODO: Move this to IdentityManager
      emailToSlackUserId = slackManager.getEmailToUserIdMapping();
    }
    return emailToSlackUserId.get(email);
  }
}
