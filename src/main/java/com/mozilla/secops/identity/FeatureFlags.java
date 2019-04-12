package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FeatureFlags {
  private boolean slackConfirmationAlert;

  /**
   * Return if slack confirmation alert is enabled.
   *
   * @return Boolean to indicate whether slack confirmation alert is enabled.
   */
  @JsonProperty("slack_confirmation_alert")
  public Boolean getSlackConfirmationAlert() {
    return slackConfirmationAlert;
  }
}
