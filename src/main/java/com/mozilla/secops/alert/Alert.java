package com.mozilla.secops.alert;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
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
  private ReentrantLock metaLock;
  private AlertSeverity severity;

  /** Construct new alert object */
  public Alert() {
    alertId = UUID.randomUUID();
    timestamp = new DateTime(DateTimeZone.UTC);
    metadata = new ArrayList<AlertMeta>();
    metaLock = new ReentrantLock();
    severity = AlertSeverity.INFORMATIONAL;
  }

  private void writeObject(ObjectOutputStream o) throws IOException {
    // Override default writeObject to acquire metadata mutex to ensure we don't have
    // other threads adjusting metadata during object serialization
    metaLock.lock();
    try {
      o.defaultWriteObject();
    } finally {
      metaLock.unlock();
    }
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
   * Set alert merge key for notifications in metadata
   *
   * <p>If a merge key is set in metadata for an alert, some output transforms will utilize this key
   * to group any other alerts with the same key together to minimize generation of
   * similar/duplicate alerts.
   *
   * @param key Merge key for alert notifications
   */
  public void setNotifyMergeKey(String key) {
    addMetadata(AlertMeta.Key.NOTIFY_MERGE, key);
  }

  /**
   * Get alert merge key for notifications from metadata
   *
   * @return Merge key for alert notifications
   */
  @JsonIgnore
  public String getNotifyMergeKey() {
    return getMetadataValue(AlertMeta.Key.NOTIFY_MERGE);
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
  public String getMetadataValue(AlertMeta.Key key) {
    for (AlertMeta m : metadata) {
      if (m.getKey().equals(key.getKey())) {
        return m.getValue();
      }
    }
    return null;
  }

  /**
   * Return a custom metadata value
   *
   * <p>Custom metadata includes arbitrary keys that are not standardized, such as keys set in
   * configuration ticks. This method should not be used under normal circumstances.
   *
   * @param key Key to return data for
   * @return Value string, null if not found
   */
  public String getCustomMetadataValue(String key) {
    for (AlertMeta m : metadata) {
      if (m.getKey().equals(key)) {
        return m.getValue();
      }
    }
    return null;
  }

  /**
   * Change an existing metadata value
   *
   * <p>If the key does not exist, it will be added. Note that if multiple entries exist with the
   * same key, this method will only change the first encountered.
   *
   * @param key Key to set
   * @param value Value to set for key
   * @return True if key was successfully set
   */
  public boolean setMetadataValue(AlertMeta.Key key, String value) {
    if (!key.validate(value)) {
      return false;
    }
    metaLock.lock();
    try {
      for (AlertMeta m : metadata) {
        if (m.getKey().equals(key.getKey())) {
          m.setValue(value);
          return true;
        }
      }
      metadata.add(new AlertMeta(key.getKey(), value));
    } finally {
      metaLock.unlock();
    }
    return true;
  }

  /**
   * Get alert metadata
   *
   * @return Alert metadata
   */
  public ArrayList<AlertMeta> getMetadata() {
    if (metadata.size() == 0) {
      return null;
    }
    return metadata;
  }

  /**
   * Set alert metadata
   *
   * @param metadata ArrayList
   */
  @JsonProperty("metadata")
  public void setMetadata(ArrayList<AlertMeta> metadata) {
    this.metadata = metadata;
  }

  /**
   * Add metadata
   *
   * @param key Key
   * @param value Value
   * @return True if key was successfully set
   */
  public boolean addMetadata(AlertMeta.Key key, String value) {
    if (!key.validate(value)) {
      return false;
    }
    // Pick up metadata mutex here to prevent ConcurrentModification exception if object is
    // serialized while we are appending to the metadata, see local implementation of
    // writeObject
    metaLock.lock();
    try {
      metadata.add(new AlertMeta(key.getKey(), value));
    } finally {
      metaLock.unlock();
    }
    return true;
  }

  /**
   * Add metadata as a list of values
   *
   * <p>Only valid for LIST type fields.
   *
   * @param key Key
   * @param value List
   * @return True if key was successfully set
   */
  public boolean addMetadata(AlertMeta.Key key, List<String> value) {
    try {
      return addMetadata(key, AlertMeta.joinListValues(key, value));
    } catch (IOException exc) {
      return false;
    }
  }

  /**
   * Set a custom metadata value
   *
   * <p>Custom metadata includes arbitrary keys that are not standardized, such as keys set in
   * configuration ticks. This method should not be used under normal circumstances.
   *
   * @param key Key to set
   * @param value Value to set
   */
  public void addCustomMetadata(String key, String value) {
    // Pick up metadata mutex here to prevent ConcurrentModification exception if object is
    // serialized while we are appending to the metadata, see local implementation of
    // writeObject
    metaLock.lock();
    try {
      metadata.add(new AlertMeta(key, value));
    } finally {
      metaLock.unlock();
    }
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
   * Get alert subcategory
   *
   * @return String, or null if unset
   */
  @JsonIgnore
  public String getSubcategory() {
    return getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD);
  }

  /**
   * Set alert subcategory
   *
   * @param subcategory Subcategory string
   */
  @JsonIgnore
  public void setSubcategory(String subcategory) {
    if (category == null) {
      throw new IllegalArgumentException("attempt to set subcategory with no category");
    }

    addMetadata(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD, subcategory);
  }

  /**
   * Set email template name
   *
   * @param templateName Freemarker template name with file extension
   */
  public void setEmailTemplate(String templateName) {
    addMetadata(AlertMeta.Key.TEMPLATE_NAME_EMAIL, templateName);
  }

  /**
   * Get email template name
   *
   * @return Freemarker template name with file extension or null if not set.
   */
  @JsonIgnore
  public String getEmailTemplate() {
    return getMetadataValue(AlertMeta.Key.TEMPLATE_NAME_EMAIL);
  }

  /**
   * Set slack template name
   *
   * @param templateName Freemarker template name with file extension
   */
  public void setSlackTemplate(String templateName) {
    addMetadata(AlertMeta.Key.TEMPLATE_NAME_SLACK, templateName);
  }

  /**
   * Get slack template name
   *
   * @return Freemarker template name with file extension or null if not set.
   */
  @JsonIgnore
  public String getSlackTemplate() {
    return getMetadataValue(AlertMeta.Key.TEMPLATE_NAME_SLACK);
  }

  /**
   * Set slack catchall template name
   *
   * @param templateName Freemarker template name with file extension
   */
  public void setSlackCatchallTemplate(String templateName) {
    addMetadata(AlertMeta.Key.TEMPLATE_NAME_SLACK_CATCHALL, templateName);
  }

  /**
   * Get slack catchall template name
   *
   * @return Freemarker template name with file extension or null if not set.
   */
  @JsonIgnore
  public String getSlackCatchallTemplate() {
    return getMetadataValue(AlertMeta.Key.TEMPLATE_NAME_SLACK_CATCHALL);
  }

  /**
   * Override generated unique ID for alert
   *
   * @param alertId Alert ID for alert
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
    if (!(o instanceof Alert)) {
      return false;
    }
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
    return fromJSON(input, mapper);
  }

  /**
   * Return {@link Alert} from JSON string
   *
   * @param input Alert in JSON
   * @param mapper ObjectMapper
   * @return {@link Alert} object or null if deserialization fails.
   */
  public static Alert fromJSON(String input, ObjectMapper mapper) {
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
