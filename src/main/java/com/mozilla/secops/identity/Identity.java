package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.ArrayList;

/**
 * Represents a single identity
 */
public class Identity {
    private ArrayList<String> aliases;
    private String fragment;
    private Notify notify;

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
            if (notify.getDirectEmailNotify() != null &&
                notify.getDirectEmailNotify() == false) {
                // Explicitly disabled for identity, no notification
                return null;
            } else if (notify == null) {
                // Unset, consult global setting
                if (defaultNotification.getDirectEmailNotify() != null &&
                    defaultNotification.getDirectEmailNotify() == false) {
                    // Also disabled globally, no notification
                    return null;
                }
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
}
