package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Payload parser for AMO docker logs */
public class AmoDocker extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String reLogin = "^User \\(\\d+: ([^)]+)\\) logged in successfully";
  private final String reNewVersion =
      "^New version: <Version: ([^>]+)> \\((\\d+)\\) from <FileUpload: [^>]+>";
  private final String reGotProfile = "^Got profile.*'email': ?'([^']+)'.*";
  private final String reFileUpload = "^FileUpload created: \\S+$";
  private final String reRestricted =
      "^Restricting request from (email|ip) (\\S+) \\(reputation=.*";
  private final String reFileUploadMnt = "^UPLOAD: '([^']+)' \\((\\d+) bytes\\).*";

  public enum EventType {
    /** Login event */
    LOGIN,
    /** New addon upload */
    NEWVERSION,
    /** FxA profile fetch */
    GOTPROFILE,
    /** File upload */
    FILEUPLOAD,
    /** Restricted request */
    RESTRICTED,
    /** File upload with file system indicator */
    FILEUPLOADMNT
  }

  private String msg;
  private String uid;
  private String fxaEmail;
  private String restrictedValue;

  private String addonVersion;
  private String addonId;
  private String fileName;
  private Integer bytes;

  private EventType type;

  /**
   * Get event type
   *
   * @return EventType
   */
  public EventType getEventType() {
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
   * Get addon version
   *
   * @return String
   */
  public String getAddonVersion() {
    return addonVersion;
  }

  /**
   * Get FxA profile email
   *
   * @return String
   */
  public String getFxaEmail() {
    return fxaEmail;
  }

  /**
   * Get addon ID
   *
   * @return String
   */
  public String getAddonId() {
    return addonId;
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
   * Get UID
   *
   * @return String
   */
  public String getUid() {
    return uid;
  }

  /**
   * Get restricted value
   *
   * @return String
   */
  public String getRestrictedValue() {
    return restrictedValue;
  }

  /**
   * Get file name
   *
   * @return String
   */
  public String getFileName() {
    return fileName;
  }

  /**
   * Get bytes
   *
   * @return Integer
   */
  public Integer getBytes() {
    return bytes;
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    // There should always have an associated Mozlog hint
    Mozlog hint = state.getMozlogHint();
    if (hint == null) {
      return false;
    }
    String logger = hint.getLogger();
    if ((logger != null) && (logger.startsWith("http_app_addons"))) {
      return true;
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.AMODOCKER;
  }

  /** Construct matcher object. */
  public AmoDocker() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public AmoDocker(String input, Event e, ParserState state) {
    Map<String, String> fields = Parser.convertJsonToMap(input);
    if (fields == null) {
      return;
    }
    msg = fields.get("msg");
    String remoteIp = fields.get("remoteAddressChain");
    uid = fields.get("uid");

    if ((msg == null) || (remoteIp == null) || (uid == null)) {
      return;
    }
    // Set source address; pass null for the normalized component since we don't want to
    // set the fields in there for this event type
    setSourceAddress(remoteIp, state, null);

    if ((fields.get("email") != null) && (!fields.get("email").isEmpty())) {
      // Some log messages will have an email field to indicate the email address associated
      // with the account. If we have one, set this in the fxaEmail field.
      fxaEmail = fields.get("email");
    }

    Matcher mat = Pattern.compile(reLogin).matcher(msg);
    if (mat.matches()) {
      type = EventType.LOGIN;
      // UID field will not be set in this case, so override from the msg
      uid = mat.group(1);
      // XXX We could set normalized authentication fields here, but for now just leave
      // this out.
      return;
    }

    mat = Pattern.compile(reNewVersion).matcher(msg);
    if (mat.matches()) {
      type = EventType.NEWVERSION;
      addonVersion = mat.group(1);
      addonId = mat.group(2);
      return;
    }

    mat = Pattern.compile(reGotProfile).matcher(msg);
    if (mat.matches()) {
      type = EventType.GOTPROFILE;
      // Prefer the email field over the parsed value, but if it is unset then just grab
      // it here
      if (fxaEmail == null) {
        fxaEmail = mat.group(1);
      }
      return;
    }

    mat = Pattern.compile(reFileUpload).matcher(msg);
    if (mat.matches()) {
      type = EventType.FILEUPLOAD;
      return;
    }

    mat = Pattern.compile(reRestricted).matcher(msg);
    if (mat.matches()) {
      // Only set the restricted type field if it is a type of restriction message
      // that is applicable to the pipeline
      if (mat.group(1).equals("email")) {
        restrictedValue = mat.group(2);
        type = EventType.RESTRICTED;
      } else if (mat.group(1).equals("ip")) {
        restrictedValue = getSourceAddress();
        type = EventType.RESTRICTED;
      }
      return;
    }

    mat = Pattern.compile(reFileUploadMnt).matcher(msg);
    if (mat.matches()) {
      type = EventType.FILEUPLOADMNT;
      fileName = mat.group(1);
      bytes = new Integer(mat.group(2));
      return;
    }
  }
}
