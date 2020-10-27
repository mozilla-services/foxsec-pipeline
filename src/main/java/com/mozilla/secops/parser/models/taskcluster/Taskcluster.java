package com.mozilla.secops.parser.models.taskcluster;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** Describes the format of a Taskcluster event */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Taskcluster implements Serializable {
  private static final long serialVersionUID = 1L;

  private String apiVersion;
  private String clientId;
  private Double duration;
  private String expires;
  private Boolean authenticated;
  private String method;
  private String name;
  private Boolean isPublic;
  private String resource;
  private String[] satisfyingScopes;
  private String sourceIp;
  private Integer statusCode;

  /**
   * Get api version
   *
   * @return String
   */
  @JsonProperty("apiVersion")
  public String getApiVersion() {
    return apiVersion;
  }

  /**
   * Get client ID
   *
   * @return String
   */
  @JsonProperty("clientId")
  public String getClientId() {
    return clientId;
  }

  /**
   * Get duration
   *
   * @return Double
   */
  @JsonProperty("duration")
  public Double getDuration() {
    return duration;
  }

  /**
   * Get expires
   *
   * @return String
   */
  @JsonProperty("expires")
  public String getExpires() {
    return expires;
  }

  /**
   * Get authenticated
   *
   * @return Boolean
   */
  @JsonProperty("authenticated")
  public Boolean getAuthenticated() {
    return authenticated;
  }

  /**
   * Get method
   *
   * @return String
   */
  @JsonProperty("method")
  public String getMethod() {
    return method;
  }

  /**
   * Get name
   *
   * @return String
   */
  @JsonProperty("name")
  public String getName() {
    return name;
  }

  /**
   * Get isPublic
   *
   * @return Boolean
   */
  @JsonProperty("public")
  public Boolean getIsPublic() {
    return isPublic;
  }

  /**
   * Get resource
   *
   * @return String
   */
  @JsonProperty("resource")
  public String getResource() {
    return resource;
  }

  /**
   * Get satisfying scopes
   *
   * @return String[]
   */
  @JsonProperty("satisfyingScopes")
  public String[] getSatisfyingScopes() {
    return satisfyingScopes;
  }

  /**
   * Get source IP
   *
   * @return String
   */
  @JsonProperty("sourceIp")
  public String getSourceIp() {
    return sourceIp;
  }

  /**
   * Get status code
   *
   * @return Integer
   */
  @JsonProperty("statusCode")
  public Integer getStatusCode() {
    return statusCode;
  }

  public Taskcluster() {}
}
