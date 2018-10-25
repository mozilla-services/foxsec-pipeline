package com.mozilla.secops.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.Serializable;
import java.io.IOException;
import java.util.UUID;
import java.util.ArrayList;

/**
 * Global standardized class representing alerting output from pipelines
 */
public class Alert implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum AlertSeverity {
        /** Informational */
        @JsonProperty("info")
        INFORMATIONAL,
        /** Warning */
        @JsonProperty("warn")
        WARNING,
        /** Critical */
        @JsonProperty("critical")
        CRITICAL
    }

    private UUID alertId;
    private String summary;
    private String category;
    private ArrayList<String> payload;
    private DateTime timestamp;
    private ArrayList<AlertMeta> metadata;
    private AlertSeverity severity;

    /**
     * Construct new alert object
     */
    public Alert() {
        alertId = UUID.randomUUID();
        timestamp = new DateTime(DateTimeZone.UTC);
        payload = new ArrayList<String>();
        metadata = new ArrayList<AlertMeta>();
        severity = AlertSeverity.INFORMATIONAL;
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
    @JsonProperty("summary")
    public String getSummary() {
        return summary;
    }

    /**
     * Set alert severity
     *
     * @param severity Severity
     */
    public void setSeverity(AlertSeverity severity) {
        this.severity = severity;
    }

    /**
     * Get alert severity
     *
     * @return Severity
     */
    public AlertSeverity getSeverity() {
        return severity;
    }

    /**
     * Add new line to payload buffer
     *
     * @param line Line to append to existing payload buffer
     */
    public void addToPayload(String line) {
        payload.add(line);
    }

    /**
     * Get alert payload
     *
     * @return Payload string
     */
    @JsonProperty("payload")
    public String getPayload() {
        if (payload.size() == 0) {
            return null;
        }
        return String.join("\n", payload);
    }

    /**
     * Get alert metadata
     *
     * @return Alert metadata
     */
    @JsonProperty("metadata")
    public ArrayList<AlertMeta> getMetadata() {
        if (metadata.size() == 0) {
            return null;
        }
        return metadata;
    }

    /**
     * Add metadata
     *
     * @param key Key
     * @param value Value
     */
    public void addMetadata(String key, String value) {
        metadata.add(new AlertMeta(key, value));
    }

    /**
     * Override alert timestamp
     *
     * @param timestamp Alert timestamp
     */
    public void setTimestamp(DateTime timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Get alert timestamp
     *
     * @return Timestamp
     */
    @JsonProperty("timestamp")
    public DateTime getTimestamp() {
        return timestamp;
    }

    /**
     * Set alert category
     *
     * @param category Alert category string
     */
    public void setCategory(String category) {
        this.category = category;
    }

    /**
     * Get alert category
     *
     * @return Category string
     */
    @JsonProperty("category")
    public String getCategory() {
        return category;
    }


    /**
     * Override generated unique ID for alert
     *
     * param id UUID for alert
     */
    public void setAlertId(UUID alertId) {
        this.alertId = alertId;
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

    /**
     * Return {@link Alert} from JSON string
     *
     * @param input Alert in JSON
     * @return {@link Alert} object or null if deserialization fails.
     */
    public static Alert fromJSON(String input) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JodaModule());
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                false);
        try {
            return mapper.readValue(input, Alert.class);
        } catch (IOException exc) {
            System.out.println(exc);
            return null;
        }
    }

    /**
     * Return JSON string representation.
     *
     * @return String or null if serialization fails.
     */
    public String toJSON() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JodaModule());
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                false);
        mapper.setSerializationInclusion(Include.NON_NULL);
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException exc) {
            return null;
        }
    }
}
