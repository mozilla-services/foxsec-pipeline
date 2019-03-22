package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Payload parser for Apache combined log format */
public class ApacheCombined extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String matchRe =
      "^\"([^\"]+)\" - (\\S+) \\[(\\d{1,2}/\\S{3}/\\d{4}:\\d{1,2}:\\d{1,2}:\\d{1,2} "
          + "[^\\]]+)\\] \"([^\"]+)\" (\\d+) (\\d+|-) \"([^\"]+)\" \"([^\"]+)\"$";
  private Pattern pattRe;

  private String remoteAddr;
  private String userAgent;
  private String referrer;
  private String request;
  private String remoteUser;
  private Integer bytesSent;
  private Integer status;

  private String requestMethod;
  private String requestUrl;
  private String requestPath;

  @Override
  public Boolean matcher(String input, ParserState state) {
    Matcher mat = pattRe.matcher(input);
    if (mat.matches()) {
      return true;
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.APACHE_COMBINED;
  }

  /** Construct matcher object. */
  public ApacheCombined() {
    pattRe = Pattern.compile(matchRe);
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public ApacheCombined(String input, Event e, ParserState state) {
    pattRe = Pattern.compile(matchRe);
    Matcher mat = pattRe.matcher(input);
    if (!mat.matches()) {
      return;
    }

    remoteAddr = mat.group(1);
    if (remoteAddr != null) {
      if (remoteAddr.equals("-")) {
        remoteAddr = null;
      } else {
        remoteAddr = state.getParser().applyXffAddressSelector(remoteAddr);
      }
    }

    remoteUser = mat.group(2);
    if ((remoteUser != null) && (remoteUser.equals("-"))) {
      remoteUser = null;
    }

    request = mat.group(4);

    status = new Integer(mat.group(5));

    String bsv = mat.group(6);
    if ((bsv != null) && (!bsv.equals("-"))) {
      bytesSent = new Integer(bsv);
    }

    referrer = mat.group(7);
    if ((referrer != null) && (referrer.equals("-"))) {
      referrer = null;
    }

    userAgent = mat.group(8);
    if ((userAgent != null) && (userAgent.equals("-"))) {
      userAgent = null;
    }

    if (request != null) {
      String[] parts = request.split(" ");
      if (parts.length == 3) {
        requestMethod = parts[0];
        requestUrl = parts[1];
      }
    }

    if (requestUrl != null) {
      String[] parts = requestUrl.split("\\?");
      if (parts.length > 1) {
        requestPath = parts[0];
      } else {
        requestPath = requestUrl;
      }
    }

    Normalized n = e.getNormalized();
    n.addType(Normalized.Type.HTTP_REQUEST);
    n.setSourceAddress(remoteAddr);
    n.setUserAgent(userAgent);
    n.setRequestMethod(requestMethod);
    n.setRequestStatus(status);
    n.setRequestUrl(requestUrl);
    n.setUrlRequestPath(requestPath);
  }

  /**
   * Get request URL.
   *
   * @return Request URL string.
   */
  public String getRequestUrl() {
    return requestUrl;
  }

  /**
   * Get user agent.
   *
   * @return User agent string.
   */
  public String getUserAgent() {
    return userAgent;
  }

  /**
   * Get request method.
   *
   * @return Request method string.
   */
  public String getRequestMethod() {
    return requestMethod;
  }

  /**
   * Get request.
   *
   * @return Request string.
   */
  public String getRequest() {
    return request;
  }

  /**
   * Get source address.
   *
   * @return Source address string.
   */
  public String getSourceAddress() {
    return remoteAddr;
  }

  /**
   * Get remote user
   *
   * @return Remote user string
   */
  public String getRemoteUser() {
    return remoteUser;
  }

  /**
   * Get status.
   *
   * @return status integer.
   */
  public Integer getStatus() {
    return status;
  }

  /**
   * Get referrer
   *
   * @return Referrer string.
   */
  public String getReferrer() {
    return referrer;
  }
}
