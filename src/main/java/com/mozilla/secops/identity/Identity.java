package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

/** Represents a single identity */
public class Identity {
  private ArrayList<String> aliases;
  private NotificationPreferences notify;
  private NotificationPreferences alert;
  private String escalateTo;

  /**
   * Get escalate to email address
   *
   * @return Escalation email
   */
  @JsonProperty("escalate_to")
  public String getEscalateTo() {
    return escalateTo;
  }

  /**
   * Get username aliases for identity
   *
   * @return Aliases
   */
  @JsonProperty("aliases")
  public ArrayList<String> getAliases() {
    return aliases;
  }

  /**
   * Get notification preferences for identity
   *
   * @return {@link NotificationPreferences}
   */
  @JsonProperty("notify")
  public NotificationPreferences getNotify() {
    return notify;
  }

  /**
   * Get alerting preferences for identity
   *
   * @return {@link NotificationPreferences}
   */
  @JsonProperty("alert")
  public NotificationPreferences getAlert() {
    return alert;
  }

  /** Returns true if this identity should be notified via slack */
  @JsonIgnore
  public Boolean shouldNotifyViaSlack() {
    if (notify == null || notify.getMethod() == null) {
      return false;
    }
    return notify.getMethod() == NotificationPreferences.Method.SLACK;
  }

  /** Returns true if this identity should be notified via email */
  @JsonIgnore
  public Boolean shouldNotifyViaEmail() {
    if (notify == null || notify.getMethod() == null) {
      return false;
    }
    return notify.getMethod() == NotificationPreferences.Method.EMAIL;
  }

  /** Returns true if this identity should be alerted via slack */
  @JsonIgnore
  public Boolean shouldAlertViaSlack() {
    if (alert == null || alert.getMethod() == null) {
      return false;
    }
    return alert.getMethod() == NotificationPreferences.Method.SLACK;
  }

  /** Returns true if this identity should be alerted via email */
  @JsonIgnore
  public Boolean shouldAlertViaEmail() {
    if (alert == null || alert.getMethod() == null) {
      return false;
    }
    return alert.getMethod() == NotificationPreferences.Method.EMAIL;
  }
}
