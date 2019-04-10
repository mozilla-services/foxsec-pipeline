package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Identity notification preferences */
public class Notify {
  private Boolean directEmailNotify;
  private String directEmailNotifyFormat;
  private Boolean directSlackNotify;
  private Boolean directSlackConfirmationNotify;

  /**
   * Return if identity should be directly notified via email
   *
   * @return Boolean to indicate direct notification via email
   */
  @JsonProperty("direct_email_notify")
  public Boolean getDirectEmailNotify() {
    return directEmailNotify;
  }

  /**
   * Return if identity should be directly notified via Slack
   *
   * @return Boolean to indicate direct notification via Slack
   */
  @JsonProperty("direct_slack_notify")
  public Boolean getDirectSlackNotify() {
    return directSlackNotify;
  }

  /**
   * Return if identity should be directly notified via Slack using confirmation alert
   *
   * @return Boolean to indicate direct notification via Slack using confirmation alert
   */
  @JsonProperty("direct_slack_confirmation_notify")
  public Boolean getDirectSlackConfirmationNotify() {
    return directSlackConfirmationNotify;
  }

  /**
   * Format string to use for construction of direct email notification
   *
   * @return Format string to use for email notification address
   */
  @JsonProperty("direct_email_notify_format")
  public String getDirectEmailNotifyFormat() {
    return directEmailNotifyFormat;
  }
}
