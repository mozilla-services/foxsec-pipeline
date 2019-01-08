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

  public Boolean confirmationAlert(Alert a, String userId) throws IOException, SlackApiException {
    log.info("generating slack message for {}", userId);
    // TODO: Will probably want to construct an alert message with more context.
    return slackManager.sendConfirmationRequestToUser(userId, a.getSummary());
  }

  public String getUserId(String email) throws IOException, SlackApiException {
    if (emailToSlackUserId == null) {
      // TODO: Move this to IdentityManager
      emailToSlackUserId = slackManager.getEmailToUserIdMapping();
    }
    return emailToSlackUserId.get(email);
  }
}
