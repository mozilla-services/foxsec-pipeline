package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Payload parser for BMO Mozlog audit data */
public class BmoAudit extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String reLogin = "^successful login of (\\S+) from (\\S+) using \"([^\"]+)\",.*";
  private final String reCreate = "^(\\S+) <([^>]+)> created bug.*";

  public enum AuditType {
    /** Login event */
    LOGIN,
    /** Bug creation */
    CREATEBUG
  }

  private String msg;
  private String requestId;
  private String user;
  private String userAgent;
  private AuditType type;

  /**
   * Get audito event type
   *
   * @return AuditType
   */
  public AuditType getAuditType() {
    return type;
  }

  /**
   * Get msg
   *
   * @return String
   */
  public String getMsg() {
    return msg;
  }

  /**
   * Get remote IP
   *
   * @return String
   */
  public String getRemoteIp() {
    return getSourceAddress();
  }

  /**
   * Get request ID
   *
   * @return String
   */
  public String getRequestId() {
    return requestId;
  }

  /**
   * Get user
   *
   * @return String
   */
  public String getUser() {
    return user;
  }

  /**
   * Get user agent
   *
   * @return String
   */
  public String getUserAgent() {
    return userAgent;
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    // There should always have an associated Mozlog hint
    Mozlog hint = state.getMozlogHint();
    if (hint == null) {
      return false;
    }
    String type = hint.getType();
    if ((type == null) || (!(type.equals("audit")))) {
      return false;
    }
    Map<String, String> fields = Parser.convertJsonToMap(input);
    if (fields == null) {
      return false;
    }
    if ((fields.get("msg") != null)
        && (fields.get("remote_ip") != null)
        && (fields.get("request_id") != null)) {
      String msg = fields.get("msg");
      if (Pattern.compile(reLogin).matcher(msg).matches()) {
        return true;
      } else if (Pattern.compile(reCreate).matcher(msg).matches()) {
        return true;
      }
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.BMOAUDIT;
  }

  /** Construct matcher object. */
  public BmoAudit() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public BmoAudit(String input, Event e, ParserState state) {
    Map<String, String> fields = Parser.convertJsonToMap(input);
    if (fields == null) {
      return;
    }
    msg = fields.get("msg");
    String remoteIp = fields.get("remote_ip");
    requestId = fields.get("request_id");

    if ((msg == null) || (remoteIp == null) || (requestId == null)) {
      return;
    }
    setSourceAddress(remoteIp, state, e.getNormalized());

    Normalized n = e.getNormalized();

    Matcher mat = Pattern.compile(reLogin).matcher(msg);
    if (mat.matches()) {
      type = AuditType.LOGIN;
      user = mat.group(1);
      // Prefer the source address in the fields to the msg entry, so just ignore that group
      // here for now.
      userAgent = mat.group(3);

      n.addType(Normalized.Type.AUTH);
      n.setSubjectUser(user);
      n.setObject("bugzilla"); // Just hardcode to application here
      return;
    }

    mat = Pattern.compile(reCreate).matcher(msg);
    if (mat.matches()) {
      type = AuditType.CREATEBUG;
      user = mat.group(1);
      // Prefer the soruce address in the fields to the msg entry, so just ignore that group
      // here for now.
      n.addType(Normalized.Type.AUTH_SESSION); // Existing authenticated session
      n.setSubjectUser(user);
      n.setObject("bugzilla"); // Just hardcode to application here
    }
  }
}
