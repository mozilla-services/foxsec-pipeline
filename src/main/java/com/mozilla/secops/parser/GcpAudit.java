package com.mozilla.secops.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.google.api.services.servicecontrol.v1.model.AuditLog;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;

/** Payload parser for GCP audit log data. */
public class GcpAudit extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final JacksonFactory jfmatcher;
  private AuditLog auditLog;

  @Override
  public Boolean matcher(String input, ParserState state) {
    try {
      LogEntry entry = state.getLogEntryHint();
      if (entry == null) {
        JsonParser jp = jfmatcher.createJsonParser(input);
        entry = jp.parse(LogEntry.class);
      }

      Map<String, Object> m = entry.getProtoPayload();
      if (m == null) {
        return false;
      }
      String eType = (String) m.get("@type");
      if (eType != null) {
        if (eType.equals("type.googleapis.com/google.cloud.audit.AuditLog")) {
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
    return Payload.PayloadType.GCPAUDIT;
  }

  /**
   * Return processed AuditLog object
   *
   * @return AuditLog or null if not set
   */
  public AuditLog getAuditLog() {
    return auditLog;
  }

  /** Construct matcher object. */
  public GcpAudit() {
    jfmatcher = new JacksonFactory();
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public GcpAudit(String input, Event e, ParserState state) {
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

    String pbuf = null;
    try {
      ObjectMapper mapper = new ObjectMapper();
      pbuf = mapper.writeValueAsString(entry.getProtoPayload());
    } catch (JsonProcessingException exc) {
      return;
    }
    if (pbuf == null) {
      return;
    }
    try {
      auditLog = (new JacksonFactory()).createJsonParser(pbuf).parse(AuditLog.class);
    } catch (IOException exc) {
      return;
    }
  }
}
