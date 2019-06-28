package com.mozilla.secops.parser.models.etd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DetectionCategory implements Serializable {
  private static final long serialVersionUID = 1L;

  private String indicator;
  private String ruleName;
  private String technique;

  /**
   * Get indicator
   *
   * @return String
   */
  @JsonProperty("indicator")
  public String getIndicator() {
    return indicator;
  }

  /**
   * Get rule name which triggered finding
   *
   * @return String
   */
  @JsonProperty("ruleName")
  public String getRuleName() {
    return ruleName;
  }

  /**
   * Get bad-actor's suspected technique, i.e. "Malware", "Bruteforce", etc...
   *
   * @return String
   */
  @JsonProperty("technique")
  public String getTechnique() {
    return technique;
  }

  @Override
  public boolean equals(Object o) {
    DetectionCategory dc = (DetectionCategory) o;
    return dc.getIndicator().equals(indicator)
        && dc.getRuleName().equals(ruleName)
        && dc.getTechnique().equals(technique);
  }

  @Override
  public int hashCode() {
    return indicator.hashCode();
  }

  public DetectionCategory() {}
}
