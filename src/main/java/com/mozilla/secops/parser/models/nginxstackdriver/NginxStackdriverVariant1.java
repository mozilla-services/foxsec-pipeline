package com.mozilla.secops.parser.models.nginxstackdriver;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** Describes format of nginx log encapsulated in Stackdriver jsonPayload, variant 1 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NginxStackdriverVariant1 implements Serializable {
  private static final long serialVersionUID = 1L;

  private String xForwardedProto;
  private String remoteAddr;
  private String userAgent;
  private String referrer;
  private String request;
  private String remoteUser;
  private Double requestTime;
  private Integer bytesSent;
  private String trace;
  private String status;
  private String xForwardedFor;

  /**
   * Get x_forwarded_proto
   *
   * @return String
   */
  @JsonProperty("x_forwarded_proto")
  public String getXForwardedProto() {
    return xForwardedProto;
  }

  /**
   * Get remote_addr
   *
   * @return String
   */
  @JsonProperty("remote_addr")
  public String getRemoteAddr() {
    return remoteAddr;
  }

  /**
   * Get user_agent
   *
   * @return String
   */
  @JsonProperty("user_agent")
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
   * Get remote_user
   *
   * @return String
   */
  @JsonProperty("remote_user")
  public String getRemoteUser() {
    return remoteUser;
  }

  /**
   * Get request_time
   *
   * @return Double
   */
  @JsonProperty("request_time")
  public Double getRequestTime() {
    return requestTime;
  }

  /**
   * Get bytes_sent
   *
   * @return Integer
   */
  @JsonProperty("bytes_sent")
  public Integer getBytesSent() {
    return bytesSent;
  }

  /**
   * Get trace
   *
   * @return String
   */
  @JsonProperty("trace")
  public String getTrace() {
    return trace;
  }

  /**
   * Get status
   *
   * @return String
   */
  @JsonProperty("status")
  public String getStatus() {
    return status;
  }

  /**
   * Get x_forwarded_for
   *
   * @return String
   */
  @JsonProperty("x_forwarded_for")
  public String getXForwardedFor() {
    return xForwardedFor;
  }

  public NginxStackdriverVariant1() {}
}
