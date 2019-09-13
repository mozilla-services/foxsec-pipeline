package com.mozilla.secops.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;
import org.joda.time.DateTime;

/**
 * Payload parser for nginx log data
 *
 * <p>This parser currently only supports nginx log data that has been encapsulated in the
 * jsonPayload section of a Stackdriver LogEntry.
 */
public class Nginx extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private static final JacksonFactory jfmatcher = new JacksonFactory();

  private String xForwardedProto;
  private String remoteAddr;
  private String userAgent;
  private String referrer;
  private String request;
  private String remoteUser;
  private Double requestTime;
  private Integer bytesSent;
  private String trace;
  private Integer status;
  private String xForwardedFor;

  private String requestMethod;
  private String requestUrl;
  private String requestPath;

  private Boolean matchesStackdriverVariant1(Map<String, Object> m) {
    // Variant 1, GCP Stackdriver nginx stdout native
    return ((m.get("remote_addr") != null)
        && (m.get("request") != null)
        && (m.get("bytes_sent") != null)
        && (m.get("request_time") != null));
  }

  private Boolean matchesStackdriverVariant2(Map<String, Object> m) {
    // Variant 2, Stackdriver nginx ec2
    return ((m.get("remote_ip") != null)
        && (m.get("referrer") != null)
        && (m.get("req_time") != null)
        && (m.get("agent") != null)
        && (m.get("request") != null));
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    try {
      // XXX We only support processing Stackdriver encapsulated nginx log entries
      // that are present in jsonPayload right now. This needs to be adjusted to support
      // for example raw nginx log entries.
      LogEntry entry = state.getLogEntryHint();
      if (entry == null) {
        JsonParser jp = jfmatcher.createJsonParser(input);
        entry = jp.parse(LogEntry.class);
      }

      Map<String, Object> m = entry.getJsonPayload();
      if (m == null) {
        return false;
      }

      // XXX This is not very efficient but there is otherwise no way to determine the
      // JSON payload type, as no field exists to indicate the type of log message. Check if
      // we have a few of the fields we want and indicate true of they are present.
      if (matchesStackdriverVariant1(m) || matchesStackdriverVariant2(m)) {
        return true;
      }
    } catch (IOException exc) {
      // pass
    } catch (IllegalArgumentException exc) {
      // pass
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.NGINX;
  }

  /** Construct matcher object. */
  public Nginx() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public Nginx(String input, Event e, ParserState state) {
    LogEntry entry = state.getLogEntryHint();
    if (entry == null) {
      // Use method local JacksonFactory as the object is not serializable, and this event
      // may be passed around
      JacksonFactory jf = state.getGoogleJacksonFactory();
      try {
        JsonParser jp = jf.createJsonParser(input);
        entry = jp.parse(LogEntry.class);
      } catch (IOException exc) {
        return;
      }
    }

    Map<String, Object> m = entry.getJsonPayload();
    if (m == null) {
      return;
    }

    String ets = entry.getTimestamp();
    if (ets != null) {
      DateTime d = Parser.parseISO8601(ets);
      if (d != null) {
        e.setTimestamp(d);
      }
    }

    String pbuf = null;
    try {
      ObjectMapper mapper = new ObjectMapper();
      pbuf = mapper.writeValueAsString(m);
    } catch (JsonProcessingException exc) {
      return;
    }
    if (pbuf == null) {
      return;
    }

    if (matchesStackdriverVariant1(m)) {
      com.mozilla.secops.parser.models.nginxstackdriver.NginxStackdriverVariant1 nginxs;
      try {
        ObjectMapper mapper = new ObjectMapper();
        nginxs =
            mapper.readValue(
                pbuf,
                com.mozilla.secops.parser.models.nginxstackdriver.NginxStackdriverVariant1.class);
      } catch (IOException exc) {
        return;
      }

      xForwardedProto = nginxs.getXForwardedProto();
      remoteAddr = nginxs.getRemoteAddr();
      userAgent = nginxs.getUserAgent();
      referrer = nginxs.getReferrer();
      request = nginxs.getRequest();
      remoteUser = nginxs.getRemoteUser();
      requestTime = nginxs.getRequestTime();
      bytesSent = nginxs.getBytesSent();
      trace = nginxs.getTrace();
      status = new Integer(nginxs.getStatus());
      xForwardedFor = nginxs.getXForwardedFor();
    } else if (matchesStackdriverVariant2(m)) {
      com.mozilla.secops.parser.models.nginxstackdriver.NginxStackdriverVariant2 nginxs;
      try {
        ObjectMapper mapper = new ObjectMapper();
        nginxs =
            mapper.readValue(
                pbuf,
                com.mozilla.secops.parser.models.nginxstackdriver.NginxStackdriverVariant2.class);
      } catch (IOException exc) {
        return;
      }

      remoteAddr = nginxs.getRemoteIp();
      userAgent = nginxs.getUserAgent();
      referrer = nginxs.getReferrer();
      request = nginxs.getRequest();
      requestTime = new Double(nginxs.getRequestTime());
      bytesSent = new Integer(nginxs.getBytesSent());
      status = new Integer(nginxs.getCode());
    } else {
      return;
    }

    if ((remoteAddr != null) && (remoteAddr.equals("-"))) {
      remoteAddr = null;
    }
    if ((referrer != null) && (referrer.equals("-"))) {
      referrer = null;
    }

    // If an XFF address selector was configured in the parser, apply it to obtain the
    // correct client address
    remoteAddr = state.getParser().applyXffAddressSelector(remoteAddr);

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
    n.setRequestMethod(requestMethod);
    n.setRequestStatus(status);
    n.setRequestUrl(requestUrl);
    n.setUrlRequestPath(requestPath);
    n.setSourceAddress(remoteAddr);
  }

  @Override
  public String eventStringValue(EventFilterPayload.StringProperty property) {
    switch (property) {
      case NGINX_REQUESTMETHOD:
        return requestMethod;
      case NGINX_URLREQUESTPATH:
        return requestPath;
    }
    return null;
  }

  @Override
  public Integer eventIntegerValue(EventFilterPayload.IntegerProperty property) {
    switch (property) {
      case NGINX_STATUS:
        return status;
    }
    return null;
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
   * Get request path.
   *
   * @return Request path string.
   */
  public String getRequestPath() {
    return requestPath;
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
   * Get status.
   *
   * @return status integer.
   */
  public Integer getStatus() {
    return status;
  }

  /**
   * Get X forwarded for
   *
   * @return XFF string.
   */
  public String getXForwardedFor() {
    return xForwardedFor;
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
