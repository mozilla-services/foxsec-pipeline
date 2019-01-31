package com.mozilla.secops.parser.models.nginxstackdriver;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** Describes format of nginx log encapsulated in Stackdriver jsonPayload, variant 2 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NginxStackdriverVariant2 implements Serializable {
  private static final long serialVersionUID = 1L;

  private String remoteIp;
  private String userAgent;
  private String referrer;
  private String request;
  private String requestTime;
  private String bytesSent;
  private String code;

  /**
   * Get remote_ip
   *
   * @return String
   */
  @JsonProperty("remote_ip")
  public String getRemoteIp() {
    return remoteIp;
  }

  /**
   * Get agent
   *
   * @return String
   */
  @JsonProperty("agent")
  public String getUserAgent() {
    return userAgent;
  }

  /**
   * Get referrer
   *
   * @return String
   */
  @JsonProperty("referrer")
  public String getReferrer() {
    return referrer;
  }

  /**
   * Get request
   *
   * @return String
   */
  @JsonProperty("request")
  public String getRequest() {
    return request;
  }

  /**
   * Get req_time
   *
   * @return String
   */
  @JsonProperty("req_time")
  public String getRequestTime() {
    return requestTime;
  }

  /**
   * Get bytes_sent
   *
   * @return String
   */
  @JsonProperty("bytes_sent")
  public String getBytesSent() {
    return bytesSent;
  }

  /**
   * Get code
   *
   * @return String
   */
  @JsonProperty("code")
  public String getCode() {
    return code;
  }

  public NginxStackdriverVariant2() {}
}
