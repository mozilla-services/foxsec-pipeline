package com.mozilla.secops.parser.models.fxaauth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** FxA authentication server event */
@JsonIgnoreProperties(ignoreUnknown = true)
public class FxaAuth implements Serializable {
  private static final long serialVersionUID = 1L;

  private String agent;
  private String email;
  private Integer errno;
  private Boolean keys;
  private String lang;
  private String method;
  private String op;
  private String path;
  private String remoteAddressChain;
  private String service;
  private Integer status;
  private Integer t;
  private String uid;

  /**
   * Get agent
   *
   * @return String
   */
  @JsonProperty("agent")
  public String getAgent() {
    return agent;
  }

  /**
   * Get email
   *
   * @return String
   */
  @JsonProperty("email")
  public String getEmail() {
    return email;
  }

  /**
   * Get errno
   *
   * @return Integer
   */
  @JsonProperty("errno")
  public Integer getErrno() {
    return errno;
  }

  /**
   * Get keys
   *
   * @return Boolean
   */
  @JsonProperty("keys")
  public Boolean getKeys() {
    return keys;
  }

  /**
   * Get lang
   *
   * @return String
   */
  @JsonProperty("lang")
  public String getLang() {
    return lang;
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
   * Get op
   *
   * @return String
   */
  @JsonProperty("op")
  public String getOp() {
    return op;
  }

  /**
   * Get path
   *
   * @return String
   */
  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  /**
   * Get remote address chain
   *
   * @return String
   */
  @JsonProperty("remoteAddressChain")
  public String getRemoteAddressChain() {
    return remoteAddressChain;
  }

  /**
   * Get service
   *
   * @return String
   */
  @JsonProperty("service")
  public String getService() {
    return service;
  }

  /**
   * Get status
   *
   * @return Integer
   */
  @JsonProperty("status")
  public Integer getStatus() {
    return status;
  }

  /**
   * Get t
   *
   * @return Integer
   */
  @JsonProperty("t")
  public Integer getT() {
    return t;
  }

  /**
   * Get uid
   *
   * @return String
   */
  @JsonProperty("uid")
  public String getUid() {
    return uid;
  }

  public FxaAuth() {}
}
