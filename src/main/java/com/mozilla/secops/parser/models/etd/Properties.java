package com.mozilla.secops.parser.models.etd;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.ArrayList;

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

  @Override
  public boolean equals(Object o) {
    Properties pr = (Properties) o;
    return pr.getProject_id().equals(project_id)
        && pr.getLocation().equals(location)
        && pr.getSubnetwork_id().equals(subnetwork_id)
        && pr.getSubnetwork_name().equals(subnetwork_name);
  }

  @Override
  public int hashCode() {
    return project_id.hashCode()
        * location.hashCode()
        * subnetwork_id.hashCode()
        * subnetwork_id.hashCode();
  }

  public Properties() {}
}
