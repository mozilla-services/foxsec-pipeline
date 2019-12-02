package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApiGateway extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String matchRe =
      "\"requestId: (.+), ip: (.+), caller: (.+), user: (.+), requestTime: (.+), httpMethod: (.+), "
          + "resourcePath: (.+), status: (.+), protocol: (.+), responseLength: (.+)\"";
  private Pattern pattRe;

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

  @Override
  public Boolean matcher(String input, ParserState state) {

    // there are multiple common log formats for ApiGateway
    // see:
    // https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#apigateway-cloudwatch-log-formats
    // this currently only handles the format used by SubHub
    Matcher mat = pattRe.matcher(input);
    if (mat.matches()) {
      return true;
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.APIGATEWAY;
  }

  /** Construct matcher object. */
  public ApiGateway() {
    pattRe = Pattern.compile(matchRe);
  }

  /** Construct parser object. */
  public ApiGateway(String input, Event e, ParserState s) {

    pattRe = Pattern.compile(matchRe);
    Matcher mat = pattRe.matcher(input);
    if (!mat.matches()) {
      return;
    }

    requestId = convertEmptyFieldToNull(mat.group(1));
    // TODO: XFF?
    ip = convertEmptyFieldToNull(mat.group(2));
    caller = convertEmptyFieldToNull(mat.group(3));
    user = convertEmptyFieldToNull(mat.group(4));
    requestTime = convertEmptyFieldToNull(mat.group(5));
    httpMethod = convertEmptyFieldToNull(mat.group(6));
    resourcePath = convertEmptyFieldToNull(mat.group(7));
    status = Integer.valueOf(mat.group(8));
    protocol = convertEmptyFieldToNull(mat.group(9));
    responseLength = Integer.valueOf(mat.group(10));

    Normalized n = e.getNormalized();
    setSourceAddress(ip, s, n);
    n.setType(Normalized.Type.HTTP_REQUEST);
    n.setRequestMethod(httpMethod);
    n.setRequestStatus(status);
    n.setUrlRequestPath(resourcePath);
  }

  private String convertEmptyFieldToNull(String field) {
    if (field != null) {
      if (field.equals("-")) {
        return null;
      }
    }
    return field;
  }

  public String getRequestId() {
    return requestId;
  }

  public void setRequestId(String requestId) {
    this.requestId = requestId;
  }

  public String getIp() {
    return ip;
  }

  public void setIp(String ip) {
    this.ip = ip;
  }

  public String getCaller() {
    return caller;
  }

  public void setCaller(String caller) {
    this.caller = caller;
  }

  public String getUser() {
    return user;
  }

  public void setUser(String user) {
    this.user = user;
  }

  public String getRequestTime() {
    return requestTime;
  }

  public void setRequestTime(String requestTime) {
    this.requestTime = requestTime;
  }

  public String getHttpMethod() {
    return httpMethod;
  }

  public void setHttpMethod(String httpMethod) {
    this.httpMethod = httpMethod;
  }

  public String getResourcePath() {
    return resourcePath;
  }

  public void setResourcePath(String resourcePath) {
    this.resourcePath = resourcePath;
  }

  public Integer getStatus() {
    return status;
  }

  public void setStatus(Integer status) {
    this.status = status;
  }

  public String getProtocol() {
    return protocol;
  }

  public void setProtocol(String protocol) {
    this.protocol = protocol;
  }

  public Integer getResponseLength() {
    return responseLength;
  }

  public void setResponseLength(Integer responseLength) {
    this.responseLength = responseLength;
  }
}
