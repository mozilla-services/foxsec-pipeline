package com.mozilla.secops.parser.models.fxacontent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class FxaContent implements Serializable {
  private static final long serialVersionUID = 1L;

  private Integer contentLength;
  private String path;
  private String method;
  private String remoteAddressChain;
  private String t;
  private String userAgent;
  private String clientAddress;
  private Integer status;
  private String referer;

  /**
   * Get ContentLength
   *
   * @return Integer
   */
  @JsonProperty("contentlength")
  public Integer getContentLength() {
    return contentLength;
  }

  /**
   * Get Path
   *
   * @return String
   */
  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  /**
   * Get Method
   *
   * @return String
   */
  @JsonProperty("method")
  public String getMethod() {
    return method;
  }

  /**
   * Get remote address chain
   *
   * @return String
   */
  @JsonProperty("remoteaddresschain")
  public String getRemoteAddressChain() {
    return remoteAddressChain;
  }

  /**
   * Get t
   *
   * @return String
   */
  @JsonProperty("t")
  public String getT() {
    return t;
  }

  /**
   * Get userAgent
   *
   * @return String
   */
  @JsonProperty("useragent")
  public String getUserAgent() {
    return userAgent;
  }

  /**
   * Get client address
   *
   * @return String
   */
  @JsonProperty("clientaddress")
  public String getClientAddress() {
    return clientAddress;
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
   * Get referer
   *
   * @return String
   */
  @JsonProperty("referer")
  public String getReferer() {
    return referer;
  }
}
