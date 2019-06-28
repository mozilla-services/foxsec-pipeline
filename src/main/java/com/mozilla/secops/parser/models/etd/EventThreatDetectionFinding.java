package com.mozilla.secops.parser.models.etd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.ArrayList;

/** Describes the format of a GCP Event Threat Detection Finding */
@JsonIgnoreProperties(ignoreUnknown = true)
public class EventThreatDetectionFinding implements Serializable {
  private static final long serialVersionUID = 1L;

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

    public DetectionCategory() {}
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class Evidence implements Serializable {
    private static final long serialVersionUID = 1L;

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

    private SourceLogId sourceLogId;

    @JsonProperty("sourceLogId")
    public SourceLogId getSourceLogId() {
      return sourceLogId;
    }

    public Evidence() {}
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public class Properties implements Serializable {
    private static final long serialVersionUID = 1L;

    private String ip;
    private String location;
    private String project_id;
    private String subnetwork_id;
    private String subnetwork_name;
    private ArrayList<String> domain;

    /**
     * Get IP
     *
     * @return String
     */
    @JsonProperty("ip")
    public String getIp() {
      return ip;
    }

    /**
     * Get GCP location (analogous to AWS region)
     *
     * @return String
     */
    @JsonProperty("location")
    public String getLocation() {
      return location;
    }

    /**
     * Get GCP project id for ETD
     *
     * @return String
     */
    @JsonProperty("project_id")
    public String getProject_id() {
      return project_id;
    }

    /**
     * Get subnet id
     *
     * @return String
     */
    @JsonProperty("subnetwork_id")
    public String getSubnetwork_id() {
      return subnetwork_id;
    }

    /**
     * Get subnet name
     *
     * @return String
     */
    @JsonProperty("subnetwork_name")
    public String getSubnetwork_name() {
      return subnetwork_name;
    }

    /**
     * Get domain list
     *
     * @return ArrayList<String>
     */
    @JsonProperty("domain")
    public ArrayList<String> getDomain() {
      return domain;
    }

    public Properties() {}
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public class SourceId implements Serializable {
    private static final long serialVersionUID = 1L;

    private String customerOrganizationNumber;
    private String projectId;

    /**
     * Get GCP org number
     *
     * @return String
     */
    @JsonProperty("customerOrganizationNumber")
    public String getCustomerOrganizationNumber() {
      return customerOrganizationNumber;
    }

    /**
     * Get GCP project id for source of Finding
     *
     * @return String
     */
    @JsonProperty("projectId")
    public String getProjectId() {
      return projectId;
    }

    public SourceId() {}
  }

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

  public EventThreatDetectionFinding() {}
}
