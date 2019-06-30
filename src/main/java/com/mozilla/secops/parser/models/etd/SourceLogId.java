package com.mozilla.secops.parser.models.etd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SourceLogId implements Serializable {
  private static final long serialVersionUID = 1L;

  private String insertId;
  private String timestamp;

  /**
   * Get insert id
   *
   * @return String
   */
  @JsonProperty("insertId")
  public String getInsertId() {
    return insertId;
  }

  /**
   * Get timestamp
   *
   * @return String
   */
  @JsonProperty("timestamp")
  public String getTimestamp() {
    return timestamp;
  }

  public SourceLogId() {}
}
