package com.mozilla.secops.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.google.api.services.servicecontrol.v1.model.AuditLog;
import com.google.api.services.servicecontrol.v1.model.AuthenticationInfo;
import com.google.api.services.servicecontrol.v1.model.AuthorizationInfo;
import com.google.api.services.servicecontrol.v1.model.RequestMetadata;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.identity.IdentityManager;
import java.io.IOException;
import java.io.Serializable;
import java.util.List;
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

    Normalized n = e.getNormalized();

    AuthenticationInfo authen = auditLog.getAuthenticationInfo();
    String subj = null;
    if (authen != null) {
      subj = authen.getPrincipalEmail();
    }

    RequestMetadata rm = auditLog.getRequestMetadata();
    String sourceAddr = null;
    if (rm != null) {
      sourceAddr = rm.getCallerIp();
    }

    String obj = null;
    List<AuthorizationInfo> author = auditLog.getAuthorizationInfo();
    if (author != null && author.size() >= 1) {
      obj = author.get(0).getResource();
    }

    if (subj != null && sourceAddr != null && obj != null) {
      n.addType(Normalized.Type.AUTH_SESSION);
      n.setSubjectUser(subj);
      n.setSourceAddress(sourceAddr);
      n.setObject(obj);

      CityResponse cr = state.getParser().geoIp(sourceAddr);
      if (cr != null) {
        n.setSourceAddressCity(cr.getCity().getName());
        n.setSourceAddressCountry(cr.getCountry().getIsoCode());
      }

      // If we have an instance of IdentityManager in the parser, see if we can
      // also set the resolved subject identity
      IdentityManager mgr = state.getParser().getIdentityManager();
      if (mgr != null) {
        String resId = mgr.lookupAlias(subj);
        if (resId != null) {
          n.setSubjectUserIdentity(resId);
        }
      }
    }
  }
}
