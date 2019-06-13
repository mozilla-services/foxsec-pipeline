package com.mozilla.secops.parser.models.aws.guardduty;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** Describes the format of an AWS GuardDuty Finding */
@JsonIgnoreProperties(ignoreUnknown = true)
public class GuardDutyFinding implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String CW_EVENT_GUARD_DUTY_DETAIL_TYPE = new String("GuardDuty Finding");

  private String schemaVersion;
  private String accountId;
  private String region;
  private String partition;
  private String id;
  private String arn;
  private String type;
  // TODO: private ? resource
  // TODO: private ? service
  private int severity;
  private String createdAt;
  private String updatedAt;
  private String title;
  private String description;

  /**
   * Get finding schema version
   *
   * @return String
   */
  @JsonProperty("schemaVersion")
  public String getSchemaVersion() {
    return schemaVersion;
  }

  /**
   * Get aws account id
   *
   * @return String
   */
  @JsonProperty("accountId")
  public String getAccountId() {
    return accountId;
  }

  /**
   * Get aws account region
   *
   * @return String
   */
  @JsonProperty("region")
  public String getRegion() {
    return region;
  }

  /**
   * Get aws partition
   *
   * @return String
   */
  @JsonProperty("partition")
  public String getPartition() {
    return partition;
  }

  /**
   * Get finding id
   *
   * @return String
   */
  @JsonProperty("id")
  public String getId() {
    return id;
  }

  /**
   * Get finding arn
   *
   * @return String
   */
  @JsonProperty("arn")
  public String getArn() {
    return arn;
  }

  /**
   * Get finding type
   *
   * @return String
   */
  @JsonProperty("type")
  public String getType() {
    return type;
  }

  /**
   * Get the finding's aws severity score
   *
   * @return String
   */
  @JsonProperty("severity")
  public int getSeverity() {
    return severity;
  }

  /**
   * Get a finding creation timestamp
   *
   * @return String
   */
  @JsonProperty("createdAt")
  public String getCreatedAt() {
    return createdAt;
  }

  /**
   * Get a finding modification timestamp
   *
   * @return String
   */
  @JsonProperty("updatedAt")
  public String getUpdatedAt() {
    return updatedAt;
  }

  /**
   * Get finding title
   *
   * @return String
   */
  @JsonProperty("title")
  public String getTitle() {
    return title;
  }

  /**
   * Get finding description
   *
   * @return String
   */
  @JsonProperty("description")
  public String getDescription() {
    return description;
  }

  public GuardDutyFinding() {}
}
