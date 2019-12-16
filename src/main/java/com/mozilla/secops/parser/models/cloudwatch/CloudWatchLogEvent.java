package com.mozilla.secops.parser.models.cloudwatch;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CloudWatchLogEvent implements Serializable {
  private static final long serialVersionUID = 1L;

  private String id;
  private Long timestamp;
  private Object message;

  /**
   * Get event id
   *
   * @return String
   */
  @JsonProperty("id")
  public String getId() {
    return id;
  }

  /**
   * Get event timestamp
   *
   * @return String
   */
  @JsonProperty("timestamp")
  public Long getTimestamp() {
    return timestamp;
  }

  /**
   * Get log message
   *
   * <p>This is a payload which must be parsed further
   *
   * @return Object
   */
  @JsonProperty("message")
  public Object getMessage() {
    return message;
  }
}
