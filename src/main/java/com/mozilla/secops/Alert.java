package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.UUID;

/**
 * Global standardized class representing alerting output from pipelines
 */
public class Alert implements Serializable {
    private static final long serialVersionUID = 1L;

    private UUID alertId;
    private String summary;

    /**
     * Construct new alert object
     */
    public Alert() {
        alertId = UUID.randomUUID();
    }

    /**
     * Set alert summary
     *
     * @param summary Alert summary string
     */
    public void setSummary(String summary) {
        this.summary = summary;
    }

    /**
     * Get alert summary
     *
     * @return Summary string
     */
    public String getSummary() {
        return summary;
    }

    /**
     * Returns unique alert ID for this alert.
     *
     * @return {@link UUID} associated with alert.
     */
    @JsonProperty("id")
    public UUID getAlertId() {
        return alertId;
    }

    @Override
    public boolean equals(Object o) {
        Alert t = (Alert)o;
        return getAlertId().equals(t.getAlertId());
    }

    @Override
    public int hashCode() {
        return alertId.hashCode();
    }
}
