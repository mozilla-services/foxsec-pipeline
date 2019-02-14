package com.mozilla.secops.alert;

import com.github.seratch.jslack.api.methods.SlackApiException;
import com.mozilla.secops.crypto.RuntimeSecrets;
import com.mozilla.secops.slack.SlackManager;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateException;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AlertSlack {
  private final AlertConfiguration cfg;
  private SlackManager slackManager;
  private final Logger log;
  private State state;

  /** Construct new alert slack object */
  public AlertSlack(AlertConfiguration cfg) {
    log = LoggerFactory.getLogger(AlertSlack.class);
    this.cfg = cfg;
    configureState();

    try {
      String slackToken = RuntimeSecrets.interpretSecret(cfg.getSlackToken(), cfg.getGcpProject());
      slackManager = new SlackManager(slackToken);
    } catch (IOException exc) {
      log.error("failed to get slack token: {}", exc.getMessage());
    }
  }

  public AlertSlack(AlertConfiguration cfg, SlackManager slackManager) {
    log = LoggerFactory.getLogger(AlertSlack.class);
    this.cfg = cfg;
    configureState();
    this.slackManager = slackManager;
  }

  private void configureState() {
    if (cfg.getMemcachedEnabled()) {
      this.state =
          new State(new MemcachedStateInterface(cfg.getMemcachedHost(), cfg.getMemcachedPort()));
    } else if (cfg.getDatastoreEnabled()) {
      this.state = new State(new DatastoreStateInterface("alerts", "alerts"));
    }
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
      return slackManager.handleSlackResponse(
          slackManager.sendMessageToChannel(cfg.getSlackCatchall(), text));
    } catch (IOException exc) {
      log.error("error sending slack alert (IOException): {}", exc.getMessage());
    } catch (SlackApiException exc) {
      log.error("error sending slack alert (SlackApiException): {}", exc.getMessage());
    }
    return false;
  }

  /**
   * Send alert to a user.
   *
   * @param a Alert
   * @param userId Slack user id
   * @return Boolean on whether the alert was sent successfully
   */
  public Boolean sendToUser(Alert a, String userId) {
    if (a == null || userId == null) {
      return false;
    }

    log.info("generating slack message for {}", userId);

    String text =
        String.format(
            "Foxsec Fraud Detection Alert\n\n%s\n%s\nAlert Id: %s",
            a.getSummary(), a.assemblePayload(), a.getAlertId());
    try {
      return slackManager.handleSlackResponse(slackManager.sendMessageToChannel(userId, text));
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

    log.info("storing state of alert for {}", userId);

    try {
      a.addMetadata("status", "NEW");
      state.initialize();
      state.set(a.getAlertId().toString(), a);
    } catch (StateException exc) {
      log.error("error saving alert state (StateException): {}", exc.getMessage());
      return false;
    }

    log.info("generating slack message for {}", userId);

    String text =
        String.format(
            "Foxsec Fraud Detection Alert\n\n%s\n%s\nAlert Id: %s",
            a.getSummary(), a.assemblePayload(), a.getAlertId());
    try {
      return slackManager.handleSlackResponse(
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
    try {
      String userId = slackManager.lookupUserIdByEmail(email);
      return userId;
    } catch (IOException exc) {
      log.error("error getting user id from slack (IOException): {}", exc.getMessage());
    } catch (SlackApiException exc) {
      log.error("error getting user id from slack (SlackApiException): {}", exc.getMessage());
    }

    return null;
  }
}
