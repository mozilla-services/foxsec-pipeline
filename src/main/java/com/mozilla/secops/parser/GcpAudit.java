package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
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

  private String principalEmail;
  private String resource;
  private String callerIp;
  private String callerIpCity;
  private String callerIpCountry;

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
    return callerIp;
  }

  /**
   * Get caller IP city
   *
   * @return Caller IP cityl
   */
  @JsonProperty("caller_ip_city")
  public String getCallerIpCity() {
    return callerIpCity;
  }

  /**
   * Get caller IP country
   *
   * @return Caller IP country
   */
  @JsonProperty("caller_ip_country")
  public String getCallerIpCountry() {
    return callerIpCountry;
  }

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
    AuditLog auditLog;
    try {
      auditLog = (new JacksonFactory()).createJsonParser(pbuf).parse(AuditLog.class);
    } catch (IOException exc) {
      return;
    }

    Normalized n = e.getNormalized();

    AuthenticationInfo authen = auditLog.getAuthenticationInfo();
    if (authen != null) {
      principalEmail = authen.getPrincipalEmail();
    }

    RequestMetadata rm = auditLog.getRequestMetadata();
    if (rm != null) {
      callerIp = rm.getCallerIp();

      if (callerIp != null) {
        CityResponse cr = state.getParser().geoIp(callerIp);
        if (cr != null) {
          callerIpCity = cr.getCity().getName();
          callerIpCountry = cr.getCountry().getIsoCode();
        }
      }
    }

    List<AuthorizationInfo> author = auditLog.getAuthorizationInfo();
    if (author != null && author.size() >= 1) {
      resource = author.get(0).getResource();
    }

    if (principalEmail != null && callerIp != null && resource != null) {
      n.addType(Normalized.Type.AUTH_SESSION);
      n.setSubjectUser(principalEmail);
      n.setSourceAddress(callerIp);
      n.setObject(resource);
      n.setSourceAddressCity(callerIpCity);
      n.setSourceAddressCountry(callerIpCountry);

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
