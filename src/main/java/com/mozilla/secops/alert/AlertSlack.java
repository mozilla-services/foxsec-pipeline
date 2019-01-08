package com.mozilla.secops.alert;

import com.github.seratch.jslack.api.methods.SlackApiException;
import com.mozilla.secops.slack.SlackManager;
import java.io.IOException;
import java.util.HashMap;

public class AlertSlack {
  private final AlertConfiguration cfg;
  private SlackManager slackManager;
  private HashMap<String, String> emailToSlackUserId;

  public AlertSlack(AlertConfiguration cfg) {
    slackManager = new SlackManager(cfg.getSlackToken());
    this.cfg = cfg;
  }

  public Boolean confirmationAlert(String userId, String message)
      throws IOException, SlackApiException {
    return slackManager.sendConfirmationRequestToUser(userId, message);
  }

  public String getUserId(String email) throws IOException, SlackApiException {
    if (emailToSlackUserId == null) {
      // TODO: Move this to IdentityManager
      emailToSlackUserId = slackManager.getEmailToUserIdMapping();
    }
    return emailToSlackUserId.get(email);
  }
}
