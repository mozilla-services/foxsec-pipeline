package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import com.google.api.services.servicecontrol.v1.model.AuditLog;
import com.google.api.services.servicecontrol.v1.model.AuthenticationInfo;
import com.google.api.services.servicecontrol.v1.model.AuthorizationInfo;
import com.google.api.services.servicecontrol.v1.model.RequestMetadata;
import com.mozilla.secops.identity.IdentityManager;
import java.io.IOException;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

/** Payload parser for GCP audit log data. */
public class GcpAudit extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final GsonFactory jfmatcher;

  private String principalEmail;
  private String resource;

  /**
   * Get principal email
   *
   * @return Principal email
   */
  @JsonProperty("principal_email")
  public String getPrincipalEmail() {
    return principalEmail;
  }

  /**
   * Get resource
   *
   * @return Resource
   */
  @JsonProperty("resource")
  public String getResource() {
    return resource;
  }

  /**
   * Get caller IP address
   *
   * @return Caller IP address
   */
  @JsonProperty("caller_ip")
  public String getCallerIp() {
    return getSourceAddress();
  }

  /**
   * Get caller IP city
   *
   * @return Caller IP cityl
   */
  @JsonProperty("caller_ip_city")
  public String getCallerIpCity() {
    return getSourceAddressCity();
  }

  /**
   * Get caller IP country
   *
   * @return Caller IP country
   */
  @JsonProperty("caller_ip_country")
  public String getCallerIpCountry() {
    return getSourceAddressCountry();
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    JsonParser jp = null;
    try {
      LogEntry entry = state.getLogEntryHint();
      if (entry == null) {
        jp = jfmatcher.createJsonParser(input);
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
    } finally {
      if (jp != null) {
        try {
          jp.close();
        } catch (IOException exc) {
          throw new RuntimeException(exc.getMessage());
        }
      }
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.GCPAUDIT;
  }

  /** Construct matcher object. */
  public GcpAudit() {
    jfmatcher = new GsonFactory();
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
      GsonFactory jf = new GsonFactory();
      JsonParser jp = null;
      try {
        jp = jf.createJsonParser(input);
        entry = jp.parse(LogEntry.class);
      } catch (IOException exc) {
        return;
      } finally {
        if (jp != null) {
          try {
            jp.close();
          } catch (IOException exc) {
            throw new RuntimeException(exc.getMessage());
          }
        }
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
    AuditLog auditLog;
    JsonParser jp = null;
    try {
      jp = new GsonFactory().createJsonParser(pbuf);
      auditLog = jp.parse(AuditLog.class);
    } catch (IOException exc) {
      return;
    } finally {
      if (jp != null) {
        try {
          jp.close();
        } catch (IOException exc) {
          throw new RuntimeException(exc.getMessage());
        }
      }
    }

    Normalized n = e.getNormalized();

    AuthenticationInfo authen = auditLog.getAuthenticationInfo();
    if (authen != null) {
      principalEmail = authen.getPrincipalEmail();
    }

    RequestMetadata rm = auditLog.getRequestMetadata();
    if (rm != null) {
      String callerIp = rm.getCallerIp();

      if (callerIp != null) {
        setSourceAddress(callerIp, state, e.getNormalized());
      }
    }

    List<AuthorizationInfo> author = auditLog.getAuthorizationInfo();
    if (author != null && author.size() >= 1) {
      resource = author.get(0).getResource();
    }

    if (principalEmail != null && getSourceAddress() != null && resource != null) {
      n.addType(Normalized.Type.AUTH_SESSION);
      n.setSubjectUser(principalEmail);
      n.setObject(resource);

      // If we have an instance of IdentityManager in the parser, see if we can
      // also set the resolved subject identity
      IdentityManager mgr = state.getParser().getIdentityManager();
      if (mgr != null) {
        String resId = mgr.lookupAlias(principalEmail);
        if (resId != null) {
          n.setSubjectUserIdentity(resId);
        }
      }
    }
  }
}
