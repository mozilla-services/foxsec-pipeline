package com.mozilla.secops.parser.models.amo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** Describes the format of an AMO event */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Amo implements Serializable {
  private static final long serialVersionUID = 1L;

  private String msg;
  private String uid;
  private String remoteAddressChain;
  private String email;
  private String guid;
  private Boolean fromApi;
  private Integer numericUserId;
  private String upload;

  /**
   * Get msg
   *
   * @return String
   */
  @JsonProperty("msg")
  public String getMsg() {
    return msg;
  }

  /**
   * Set uid
   *
   * @param uid Value
   */
  @JsonProperty("uid")
  public void setUid(String uid) {
    this.uid = uid;
  }

  /**
   * Get uid
   *
   * @return String
   */
  public String getUid() {
    return uid;
  }

  /**
   * Get remoteAddressChain
   *
   * @return String
   */
  @JsonProperty("remoteAddressChain")
  public String getRemoteAddressChain() {
    return remoteAddressChain;
  }

  /**
   * Set email
   *
   * @param email Value
   */
  @JsonProperty("email")
  public void setEmail(String email) {
    this.email = email;
  }

  /**
   * Get email
   *
   * @return String
   */
  public String getEmail() {
    return email;
  }

  /**
   * Set GUID
   *
   * @param guid Value
   */
  @JsonProperty("guid")
  void setGuid(String guid) {
    if (guid != null) {
      this.guid = guid.replace("{", "");
      this.guid = this.guid.replace("}", "");
    }
  }

  /**
   * Get GUID
   *
   * @return String
   */
  public String getGuid() {
    return guid;
  }

  /**
   * Get from API flag
   *
   * @return Boolean
   */
  @JsonProperty("from_api")
  public Boolean getFromApi() {
    return fromApi;
  }

  /**
   * Get numeric user ID
   *
   * @return Integer
   */
  @JsonProperty("user_id")
  public Integer getNumericUserId() {
    return numericUserId;
  }

  /**
   * Get upload
   *
   * @return String
   */
  @JsonProperty("upload")
  public String getUpload() {
    return upload;
  }

  public Amo() {}
}
