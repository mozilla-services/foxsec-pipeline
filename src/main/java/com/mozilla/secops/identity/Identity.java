package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Represents a single identity */
public class Identity {
  private ArrayList<String> aliases;
  private NotificationPreferences notify;
  private NotificationPreferences alert;
  private String escalateTo;

  private Logger log = LoggerFactory.getLogger(Identity.class);

  /**
   * Analyze identity, logging warnings if required
   *
   * <p>Review identity configuration and log any possible issues with the configuration as
   * warnings. Purely informational and will not throw exceptions if misconfigurations exist.
   *
   * @param identity The identity key associated with this identity
   */
  public void logWarnings(String identity) {
    if ((!shouldNotifyViaSlack()) && (!shouldNotifyViaEmail())) {
      log.warn("{}: warning, no notification configuration for identity", identity);
    }
    if ((!shouldAlertViaSlack()) && (!shouldAlertViaEmail())) {
      log.warn("{}: warning, no alerting configuration for identity", identity);
    }
  }

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

  /**
   * Returns true if this identity should be notified via slack
   *
   * @return Boolean
   */
  @JsonIgnore
  public Boolean shouldNotifyViaSlack() {
    if (notify == null || notify.getMethod() == null) {
      return false;
    }
    return notify.getMethod() == NotificationPreferences.Method.SLACK;
  }

  /**
   * Returns true if this identity should be notified via email
   *
   * @return Boolean
   */
  @JsonIgnore
  public Boolean shouldNotifyViaEmail() {
    if (notify == null || notify.getMethod() == null) {
      return false;
    }
    return notify.getMethod() == NotificationPreferences.Method.EMAIL;
  }

  /**
   * Returns true if this identity should be alerted via slack
   *
   * @return Boolean
   */
  @JsonIgnore
  public Boolean shouldAlertViaSlack() {
    if (alert == null || alert.getMethod() == null) {
      return false;
    }
    return alert.getMethod() == NotificationPreferences.Method.SLACK;
  }

  /**
   * Returns true if this identity should be alerted via email
   *
   * @return Boolean
   */
  @JsonIgnore
  public Boolean shouldAlertViaEmail() {
    if (alert == null || alert.getMethod() == null) {
      return false;
    }
    return alert.getMethod() == NotificationPreferences.Method.EMAIL;
  }
}
