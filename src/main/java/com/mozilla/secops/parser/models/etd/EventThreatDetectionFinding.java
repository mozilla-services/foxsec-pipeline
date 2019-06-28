package com.mozilla.secops.parser.models.etd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.ArrayList;

/** Describes the format of a GCP Event Threat Detection Finding */
@JsonIgnoreProperties(ignoreUnknown = true)
public class EventThreatDetectionFinding implements Serializable {
  private static final long serialVersionUID = 1L;

  private String detectionPriority;
  private String eventTime;
  private DetectionCategory detectionCategory;
  private ArrayList<Evidence> evidence;
  private Properties properties;
  private SourceId sourceId;

  /**
   * Get event detection priority / severity
   *
   * @return String
   */
  @JsonProperty("detectionPriority")
  public String getDetectionPriority() {
    return detectionPriority;
  }

  /**
   * Get event time
   *
   * @return String
   */
  @JsonProperty("eventTime")
  public String getEventTime() {
    return eventTime;
  }

  /**
   * Get event detection category object
   *
   * @return {@link DetectionCategory}
   */
  @JsonProperty("detectionCategory")
  public DetectionCategory getDetectionCategory() {
    return detectionCategory;
  }

  /**
   * Get evidence object
   *
   * @return ArrayList<{@link Evidence}>
   */
  @JsonProperty("evidence")
  public ArrayList<Evidence> getEvidence() {
    return evidence;
  }

  /**
   * Get event detection properties object
   *
   * @return {@link Properties}
   */
  @JsonProperty("properties")
  public Properties getProperties() {
    return properties;
  }

  /**
   * Get sourceId object
   *
   * @return {@link SourceId}
   */
  @JsonProperty("sourceId")
  public SourceId getSourceId() {
    return sourceId;
  }

  @Override
  public boolean equals(Object o) {
    EventThreatDetectionFinding etdf = (EventThreatDetectionFinding) o;
    return etdf.getEventTime().equals(eventTime) && (etdf.getEvidence().equals(evidence));
  }

  @Override
  public int hashCode() {
    return evidence.hashCode();
  }

  public EventThreatDetectionFinding() {}
}
