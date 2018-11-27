package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.io.Serializable;
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
  public <T extends PayloadBase> T getPayload() {
    return (T) payload.getData();
  }

  /**
   * Return the type of payload data associated with this event.
   *
   * @return {@link Payload.PayloadType}
   */
  public Payload.PayloadType getPayloadType() {
    return payload.getType();
  }

  /**
   * Get unique event ID.
   *
   * @return {@link UUID} associated with event.
   */
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
   * @param mozlog Mozlog values for event
   */
  public void setMozlog(Mozlog mozlog) {
    this.mozlog = mozlog;
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

  /**
   * Utility function to convert an iterable list of events into a JSON string
   *
   * @param input List of events for conversion
   * @return JSON string, null on failure
   */
  public static String iterableToJson(Iterable<Event> input) {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.setSerializationInclusion(Include.NON_NULL);
    try {
      return mapper.writeValueAsString(input);
    } catch (JsonProcessingException exc) {
      return null;
    }
  }
}
