package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

/** Represents a single identity */
public class Identity {
  private ArrayList<String> aliases;
  private String fragment;
  private Notify notify;
  private FeatureFlags featureFlags;
  private String escalateTo;

  /**
   * Get identity fragment
   *
   * @return Fragment string
   */
  @JsonProperty("fragment")
  public String getFragment() {
    return fragment;
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
   * @return {@link Notify}
   */
  @JsonProperty("notify")
  public Notify getNotify() {
    return notify;
  }

  /**
   * Get feature flags for identity
   *
   * @return {@link FeatureFlags}
   */
  @JsonProperty("feature_flags")
  public FeatureFlags getFeatureFlags() {
    return featureFlags;
  }

  /**
   * Resolve direct email notification target for identity
   *
   * @param defaultNotification Default notification preferences if unset in identity
   */
  public String getEmailNotifyDirect(Notify defaultNotification) {
    // If the fragment is unset, will not notify
    if (fragment == null) {
      return null;
    }

    if (notify != null) {
      if (notify.getDirectEmailNotify() != null && notify.getDirectEmailNotify() == false) {
        // Explicitly disabled for identity, no notification
        return null;
      }
    } else if (notify == null) {
      // Unset, consult global setting
      if ((defaultNotification == null)
          || (defaultNotification.getDirectEmailNotify() != null
              && defaultNotification.getDirectEmailNotify() == false)) {
        // Also disabled globally, no notification
        return null;
      }
    }

    String fstring = null;
    if (notify != null) {
      fstring = notify.getDirectEmailNotifyFormat();
    }
    if (fstring == null) {
      // Unset for identity, use global
      fstring = defaultNotification.getDirectEmailNotifyFormat();
    }
    if (fstring == null) {
      return null;
    }
    return String.format(fstring, fragment);
  }

  /**
   * Returns boolean that is true if this identity should get a direct notification via Slack
   *
   * @param defaultNotification Default notification preferences if unset in identity
   */
  public Boolean getSlackNotifyDirect(Notify defaultNotification) {
    if (notify != null) {
      if (notify.getDirectSlackNotify() != null) {
        return notify.getDirectSlackNotify();
      }
    }

    if ((defaultNotification == null)
        || (defaultNotification.getDirectSlackNotify() != null
            && defaultNotification.getDirectSlackNotify() == false)) {
      return false;
    }

    return true;
  }

  /**
   * Returns boolean that is true if this identity shoud get a slack confirmation alert.
   * getSlackNotifyDirect() must also return true for this feature flag to be used.
   *
   * @param defaultFeatureFlags Default feature flags if unset in identity
   */
  public Boolean getSlackConfirmationAlertFeatureFlag(FeatureFlags defaultFeatureFlags) {
    if (featureFlags != null) {
      if (featureFlags.getSlackConfirmationAlert() != null) {
        return featureFlags.getSlackConfirmationAlert();
      }
    }

    if ((defaultFeatureFlags == null)
        || (defaultFeatureFlags.getSlackConfirmationAlert() != null
            && defaultFeatureFlags.getSlackConfirmationAlert() == false)) {
      return false;
    }

    return true;
  }
}
