package com.mozilla.secops.parser.models.etd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Evidence implements Serializable {
  private static final long serialVersionUID = 1L;

  private SourceLogId sourceLogId;

  @JsonProperty("sourceLogId")
  public SourceLogId getSourceLogId() {
    return sourceLogId;
  }

  @Override
  public boolean equals(Object o) {
    Evidence ev = (Evidence) o;
    return ev.getSourceLogId().equals(sourceLogId);
  }

  @Override
  public int hashCode() {
    return sourceLogId.hashCode();
  }

  public Evidence() {}
}
