package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Identity notification preferences */
public class NotificationPreferences {
  private String email;
  private Method method;

  /* Notification methods supported */
  public enum Method {
    SLACK,
    EMAIL
  }

  /**
   * Return the email specified
   *
   * @return Email to use
   */
  @JsonProperty("email")
  public String getEmail() {
    return email;
  }

  /**
   * Return the notification method specified
   *
   * @return Method to use to notify a user. Either `EMAIL` or `SLACK`
   */
  @JsonProperty("method")
  public Method getMethod() {
    return method;
  }
}
