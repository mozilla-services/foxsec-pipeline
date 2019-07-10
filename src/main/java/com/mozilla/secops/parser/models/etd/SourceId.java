package com.mozilla.secops.parser.models.etd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SourceId implements Serializable {
  private static final long serialVersionUID = 1L;

  private String customerOrganizationNumber;
  private String projectNumber;

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
   * Get GCP project number for source of Finding
   *
   * @return String
   */
  @JsonProperty("projectNumber")
  public String getProjectNumber() {
    return projectNumber;
  }

  public SourceId() {}
}
