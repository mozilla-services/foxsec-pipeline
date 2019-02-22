package com.mozilla.secops.alert;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

/** Global standardized class representing alerting output from pipelines */
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
  private String payload;
  private DateTime timestamp;
  private ArrayList<AlertMeta> metadata;
  private AlertSeverity severity;

  /** Construct new alert object */
  public Alert() {
    alertId = UUID.randomUUID();
    timestamp = new DateTime(DateTimeZone.UTC);
    metadata = new ArrayList<AlertMeta>();
    severity = AlertSeverity.INFORMATIONAL;
  }

  /**
   * Determine if an alert has all mandatory fields set correctly
   *
   * <p>Pipelines should call this on any {@link Alert} object that is going to be submitted to
   * ensure it will not be dropped by the output transforms.
   *
   * @return True if alert has correct fields
   */
  public Boolean hasCorrectFields() {
    if (summary == null || summary.isEmpty()) {
      return false;
    }
    return true;
  }

  /**
   * Assemble a complete payload buffer that contains alert metadata information in addition to the
   * alert payload.
   *
   * @return Assembled payload string
   */
  public String assemblePayload() {
    String ret = getPayload();
    ArrayList<AlertMeta> meta = getMetadata();

    if (meta != null) {
      ret = ret + "\n\nAlert metadata:\n";
      for (AlertMeta m : meta) {
        ret = ret + String.format("%s = %s\n", m.getKey(), m.getValue());
      }
    }

    return ret;
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
   * Set a masked summary in the alert
   *
   * <p>Some output transforms will utilize the prefer the masked summary to the primary summary
   * field, assuming the masked summary has sensitive information removed.
   *
   * @param maskedSummary Masked summary string
   */
  public void setMaskedSummary(String maskedSummary) {
    addMetadata("masked_summary", maskedSummary);
  }

  /**
   * Get any masked summary value in the alert
   *
   * @return Masked summary or null if unset
   */
  @JsonIgnore
  public String getMaskedSummary() {
    return getMetadataValue("masked_summary");
  }

  /**
   * Set alert merge key for notifications in metadata
   *
   * <p>If a merge key is set in metadata for an alert, some output transforms will utilize this key
   * to group any other alerts with the same key together to minimize generation of
   * similar/duplicate alerts.
   *
   * @param key Merge key for alert notifications
   */
  public void setNotifyMergeKey(String key) {
    addMetadata("notify_merge", key);
  }

  /**
   * Get alert merge key for notifications from metadata
   *
   * @return Merge key for alert notifications
   */
  @JsonIgnore
  public String getNotifyMergeKey() {
    return getMetadataValue("notify_merge");
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
    if (payload == null) {
      payload = line;
    } else {
      payload = payload + "\n" + line;
    }
  }

  /**
   * Get alert payload
   *
   * @return Payload string
   */
  @JsonProperty("payload")
  public String getPayload() {
    return payload;
  }

  /**
   * Return a specific metadata value
   *
   * @param key Key to return data for
   * @return Value string, null if not found
   */
  public String getMetadataValue(String key) {
    for (AlertMeta m : metadata) {
      if (m.getKey().equals(key)) {
        return m.getValue();
      }
    }
    return null;
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
   * Set template name
   *
   * @param templateName Freemarker template name with file extension
   */
  public void setTemplateName(String templateName) {
    addMetadata("template_name", templateName);
  }

  /**
   * Get template name
   *
   * @return Freemarker template name with file extension or null if not set.
   */
  @JsonIgnore
  public String getTemplateName() {
    return getMetadataValue("template_name");
  }

  /**
   * Override generated unique ID for alert
   *
   * <p>param id UUID for alert
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
    Alert t = (Alert) o;
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
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    try {
      return mapper.readValue(input, Alert.class);
    } catch (IOException exc) {
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
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.setSerializationInclusion(Include.NON_NULL);
    try {
      return mapper.writeValueAsString(this);
    } catch (JsonProcessingException exc) {
      return null;
    }
  }

  /**
   * Return HashMap used by Freemarker to generate an HTML alert email
   *
   * @return Template data model
   */
  public HashMap<String, Object> generateTemplateVariables() {
    HashMap<String, Object> v = new HashMap<String, Object>();
    v.put("alert", this);
    for (AlertMeta m : metadata) {
      v.put(m.getKey(), m.getValue());
    }
    return v;
  }
}
