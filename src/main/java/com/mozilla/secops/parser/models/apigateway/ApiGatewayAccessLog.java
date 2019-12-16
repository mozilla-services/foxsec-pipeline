package com.mozilla.secops.parser.models.apigateway;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ApiGatewayAccessLog implements Serializable {
  private static final long serialVersionUID = 1L;

  private String requestId;
  private String ip;
  private String caller;
  private String user;
  private String requestTime;
  private String httpMethod;
  private String resourcePath;
  private Integer status;
  private String protocol;
  private Integer responseLength;

  @JsonProperty("request_id")
  public String getRequestId() {
    return requestId;
  }

  @JsonProperty("ip")
  public String getIp() {
    return ip;
  }

  @JsonProperty("caller")
  public String getCaller() {
    return caller;
  }

  @JsonProperty("user")
  public String getUser() {
    return user;
  }

  @JsonProperty("request_time")
  public String getRequestTime() {
    return requestTime;
  }

  @JsonProperty("http_method")
  public String getHttpMethod() {
    return httpMethod;
  }

  @JsonProperty("resource_path")
  public String getResourcePath() {
    return resourcePath;
  }

  @JsonProperty("status")
  public Integer getStatus() {
    return status;
  }

  @JsonProperty("protocol")
  public String getProtocol() {
    return protocol;
  }

  @JsonProperty("response_length")
  public Integer getResponseLength() {
    return responseLength;
  }

  public ApiGatewayAccessLog() {}
}
