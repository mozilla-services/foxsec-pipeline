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
  // TODO: add remaining fields here

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

  public GuardDutyFinding() {}
}
