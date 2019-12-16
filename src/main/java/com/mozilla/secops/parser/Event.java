package com.mozilla.secops.parser;

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
import java.util.Map;
import java.util.UUID;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

/**
 * Represents a high level event after being processed by a {@link Parser}.
 *
 * <p>After being parsed, all events are guaranteed to have an associated {@link Payload} value
 * which contains information related to a specific type of event.
 *
 * <p>Specific parser implementations may also add {@link Normalized} data fields to the event.
 */
public class Event implements Serializable {
  private static final long serialVersionUID = 1L;

  private Payload<? extends PayloadBase> payload;
  private final UUID eventId;
  private DateTime timestamp;
  private Normalized normalized;
  private Mozlog mozlog;
  private String stackdriverProject;
  private Map<String, String> stackdriverLabels;
  private String cloudwatchLogGroup;

  /**
   * Create a new {@link Event} object.
   *
   * <p>The default timestamp associated with the event is the current time.
   */
  Event() {
    eventId = UUID.randomUUID();
    normalized = new Normalized();

    // Default the event timestamp to creation time
    timestamp = new DateTime(DateTimeZone.UTC);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Event)) {
      return false;
    }
    Event t = (Event) o;
    return getEventId().equals(t.getEventId());
  }

  @Override
  public int hashCode() {
    return eventId.hashCode();
  }

  /**
   * Set event payload.
   *
   * @param p Payload data.
   */
  public <T extends PayloadBase> void setPayload(T p) {
    payload = new Payload<T>(p);
  }

  /**
   * Get event payload.
   *
   * @return Payload data extending {@link PayloadBase}.
   */
  @SuppressWarnings("unchecked")
  @JsonProperty("payload")
  public <T extends PayloadBase> T getPayload() {
    return (T) payload.getData();
  }

  /**
   * Return the type of payload data associated with this event.
   *
   * @return {@link Payload.PayloadType}
   */
  @JsonProperty("payload_type")
  public Payload.PayloadType getPayloadType() {
    return payload.getType();
  }

  private void setPayloadType(Payload.PayloadType value) {
    // Noop setter, required for event deserialization
  }

  /**
   * Get unique event ID.
   *
   * @return {@link UUID} associated with event.
   */
  @JsonProperty("id")
  public UUID getEventId() {
    return eventId;
  }

  /**
   * Get mozlog value
   *
   * @return {@link Mozlog} value or null if not available
   */
  public Mozlog getMozlog() {
    return mozlog;
  }

  /**
   * Set mozlog value
   *
   * <p>If the mozlog entry has a timestamp value, this timestamp will be used for the event
   * timestamp.
   *
   * @param mozlog Mozlog values for event
   */
  public void setMozlog(Mozlog mozlog) {
    this.mozlog = mozlog;

    // If we have a mozlog timestamp entry, use that for our event timestamp
    if (mozlog.getTimestamp() != null) {
      // Convert to ms for joda time
      setTimestamp(new DateTime(mozlog.getTimestamp() / 1000000));
    }
  }

  /**
   * Set Stackdriver project name
   *
   * @param project Project string
   */
  public void setStackdriverProject(String project) {
    stackdriverProject = project;
  }

  /**
   * Get Stackdriver project name
   *
   * @return Stackdriver project name, or null if was not present
   */
  @JsonProperty("stackdriver_project")
  public String getStackdriverProject() {
    return stackdriverProject;
  }

  /**
   * Set Stackdriver labels
   *
   * @param labels Labels
   */
  public void setStackdriverLabels(Map<String, String> labels) {
    if (labels == null) {
      return;
    }
    // Convert to HashMap, avoids
    // java.io.NotSerializableException: com.google.api.client.util.ArrayMap
    // on map returned from LogEntry
    stackdriverLabels = new HashMap<String, String>();
    for (Map.Entry<String, String> entry : labels.entrySet()) {
      stackdriverLabels.put(entry.getKey(), entry.getValue());
    }
  }

  /**
   * Get Stackdriver labels
   *
   * @return Labels, null if not present
   */
  @JsonProperty("stackdriver_labels")
  public Map<String, String> getStackdriverLabels() {
    return stackdriverLabels;
  }

  /**
   * Get specific Stackdriver label value
   *
   * @param key Label key to return value for
   * @return Value if present, null if not found
   */
  @JsonIgnore
  public String getStackdriverLabel(String key) {
    if (stackdriverLabels == null) {
      return null;
    }
    return stackdriverLabels.get(key);
  }

  /**
   * Get event timestamp.
   *
   * @return Timestamp associated with event.
   */
  public DateTime getTimestamp() {
    return timestamp;
  }

  /**
   * Set event timestamp.
   *
   * @param t {@link DateTime} to associate with event.
   */
  public void setTimestamp(DateTime t) {
    timestamp = t;
  }

  /**
   * Return normalized data set.
   *
   * @return {@link Normalized} data associated with event.
   */
  public Normalized getNormalized() {
    return normalized;
  }

  private static ObjectMapper getObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.setSerializationInclusion(Include.NON_NULL);
    return mapper;
  }

  /**
   * Set the CloudWatch log group
   *
   * @param project log group string
   */
  public void setCloudWatchLogGroup(String logGroup) {
    cloudwatchLogGroup = logGroup;
  }

  /**
   * Get Cloudwatch log group
   *
   * @return Stackdriver project name, or null if was not present
   */
  @JsonProperty("cloudwatchLogGroup")
  public String getCloudWatchLogGroup() {
    return cloudwatchLogGroup;
  }

  /**
   * Convert event into JSON string representation
   *
   * @return JSON string, null on failure
   */
  public String toJSON() {
    ObjectMapper mapper = getObjectMapper();
    try {
      return mapper.writeValueAsString(this);
    } catch (JsonProcessingException exc) {
      return null;
    }
  }

  /**
   * Convert a JSON string into an {@link Event}
   *
   * @param input Input JSON string
   * @return Event object or null on failure
   */
  public static Event fromJSON(String input) {
    ObjectMapper mapper = getObjectMapper();
    try {
      return mapper.readValue(input, Event.class);
    } catch (IOException exc) {
      return null;
    }
  }

  /**
   * Utility function to convert a JSON string into an iterable list of events
   *
   * @param input Input JSON string
   * @return Iterable list of events, or null on failure
   */
  public static Iterable<Event> jsonToIterable(String input) {
    ObjectMapper mapper = getObjectMapper();
    try {
      return mapper.readValue(
          input, mapper.getTypeFactory().constructCollectionType(ArrayList.class, Event.class));
    } catch (IOException exc) {
      return null;
    }
  }

  /**
   * Utility function to convert an iterable list of events into a JSON string
   *
   * @param input List of events for conversion
   * @return JSON string, null on failure
   */
  public static String iterableToJson(Iterable<Event> input) {
    ObjectMapper mapper = getObjectMapper();
    try {
      return mapper.writeValueAsString(input);
    } catch (JsonProcessingException exc) {
      return null;
    }
  }
}
