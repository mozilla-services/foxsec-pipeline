package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Identity notification preferences */
public class Notify {
  private Boolean directEmailNotify;
  private String directEmailNotifyFormat;

  /**
   * Return if identity should be directly notified
   *
   * @return Boolean to indicate direct notification
   */
  @JsonProperty("direct_email_notify")
  public Boolean getDirectEmailNotify() {
    return directEmailNotify;
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
