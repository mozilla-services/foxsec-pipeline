package com.mozilla.secops.parser;

import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.HttpRequest;
import com.google.api.services.logging.v2.model.LogEntry;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;
import org.joda.time.DateTime;

/** Payload parser for Google Load Balancer log data. */
public class GLB extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final JacksonFactory jfmatcher;

  private String requestMethod;
  private String userAgent;
  private String requestUrl;
  private String sourceAddress;
  private Integer status;

  @Override
  public Boolean matcher(String input, ParserState state) {
    try {
      LogEntry entry = state.getLogEntryHint();
      if (entry == null) {
        JsonParser jp = jfmatcher.createJsonParser(input);
        entry = jp.parse(LogEntry.class);
      }

      Map<String, Object> m = entry.getJsonPayload();
      if (m == null) {
        return false;
      }
      String eType = (String) m.get("@type");
      if (eType != null) {
        if (eType.equals(
            "type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry")) {
          return true;
        }
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
    return Payload.PayloadType.GLB;
  }

  /** Construct matcher object. */
  public GLB() {
    jfmatcher = new JacksonFactory();
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param p Parser instance.
   */
  public GLB(String input, Event e, ParserState state) {
    jfmatcher = null;
    LogEntry entry = state.getLogEntryHint();
    if (entry == null) {
      // Use method local JacksonFactory as the object is not serializable, and this event
      // may be passed around
      JacksonFactory jf = new JacksonFactory();
      try {
        JsonParser jp = jf.createJsonParser(input);
        entry = jp.parse(LogEntry.class);
      } catch (IOException exc) {
        return;
      }
    }
    HttpRequest h = entry.getHttpRequest();
    if (h == null) {
      return;
    }

    String ets = entry.getTimestamp();
    if (ets != null) {
      DateTime d = Parser.parseISO8601(ets);
      if (d != null) {
        e.setTimestamp(d);
      }
    }

    sourceAddress = h.getRemoteIp();
    requestUrl = h.getRequestUrl();
    userAgent = h.getUserAgent();
    requestMethod = h.getRequestMethod();
    status = h.getStatus();
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
   * Get source address.
   *
   * @return Source address string.
   */
  public String getSourceAddress() {
    return sourceAddress;
  }

  /**
   * Get status.
   *
   * @return status integer.
   */
  public Integer getStatus() {
    return status;
  }
}
