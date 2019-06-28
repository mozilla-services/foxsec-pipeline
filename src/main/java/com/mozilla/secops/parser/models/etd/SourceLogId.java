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

  @Override
  public boolean equals(Object o) {
    SourceLogId sli = (SourceLogId) o;
    return sli.getInsertId().equals(insertId) && sli.getTimestamp().equals(timestamp);
  }

  @Override
  public int hashCode() {
    return insertId.hashCode();
  }

  public SourceLogId() {}
}
