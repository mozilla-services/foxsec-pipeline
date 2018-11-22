package com.mozilla.secops.parser.models.duopull;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/**
 * Describes the format of a duopull event
 *
 * <p>See also https://github.com/mozilla-services/duopull-lambda
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Duopull implements Serializable {
  private static final long serialVersionUID = 1L;

  private String eventDescriptionUserId;
  private String eventObject;
  private Long eventTimestamp;
  private String eventUsername;
  private String eventFactor;
  private String eventResult;
  private String eventReason;
  private String path;
  private String msg;
  private String eventAction;

  /**
   * Get event description user ID
   *
   * @return String
   */
  @JsonProperty("event_description_user_id")
  public String getEventDescriptionUserId() {
    return eventDescriptionUserId;
  }

  /**
   * Get event object
   *
   * @return String
   */
  @JsonProperty("event_object")
  public String getEventDescriptionObject() {
    return eventObject;
  }

  /**
   * Get event timestamp
   *
   * @return Long
   */
  @JsonProperty("event_timestamp")
  public Long getEventTimestamp() {
    return eventTimestamp;
  }

  /**
   * Get event username
   *
   * @return String
   */
  @JsonProperty("event_username")
  public String getEventUsername() {
    return eventUsername;
  }

  /**
   * Get event path
   *
   * @return String
   */
  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  /**
   * Get event msg
   *
   * @return String
   */
  @JsonProperty("msg")
  public String getMsg() {
    return msg;
  }

  /**
   * Get event action
   *
   * @return String
   */
  @JsonProperty("event_action")
  public String getEventAction() {
    return eventAction;
  }

  /**
   * Get event factor
   *
   * @return String
   */
  @JsonProperty("event_factor")
  public String getEventFactor() {
    return eventFactor;
  }

  /**
   * Get event result
   *
   * @return String
   */
  @JsonProperty("event_result")
  public String getEventResult() {
    return eventResult;
  }

  /**
   * Get event reason
   *
   * @return String
   */
  @JsonProperty("event_reason")
  public String getEventReason() {
    return eventReason;
  }

  public Duopull() {}
}
