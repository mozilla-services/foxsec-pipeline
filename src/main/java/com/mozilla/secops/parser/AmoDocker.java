package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.parser.models.amo.Amo;
import java.io.IOException;
import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Payload parser for AMO docker logs */
public class AmoDocker extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String reLogin = "^User \\(\\d+: ([^)]+)\\) logged in successfully";
  private final String reNewVersion =
      "^New version: <Version: ([^>]+)> \\((\\d+)\\) from <FileUpload: [^>]+>";
  private final String reFxaLogin = "^Logging in FxA user ((.+)@(.+))$";
  private final String reFileUpload = "^FileUpload created: \\S+$";
  private final String reRestricted =
      "^Restricting request from (email|ip) (\\S+) \\(reputation=.*";
  private final String reFileUploadMnt = "^UPLOAD: '([^']+)' \\((\\d+) bytes\\).*";

  public enum EventType {
    /** Login event */
    LOGIN,
    /** New addon upload */
    NEWVERSION,
    /** FxA user login */
    FXALOGIN,
    /** File upload */
    FILEUPLOAD,
    /** Restricted request */
    RESTRICTED,
    /** File upload with file system indicator */
    FILEUPLOADMNT
  }

  private Amo amoData;

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
    return amoData.getMsg();
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
    return amoData.getEmail();
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
    return amoData.getUid();
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

  /**
   * Get API submission flag
   *
   * @return Boolean
   */
  public Boolean getFromApi() {
    return amoData.getFromApi();
  }

  /**
   * Get addon GUID
   *
   * @return String
   */
  public String getAddonGuid() {
    return amoData.getGuid();
  }

  /**
   * Get numeric user ID
   *
   * @return Integer
   */
  public Integer getUserNumericId() {
    return amoData.getNumericUserId();
  }

  /**
   * Get upload
   *
   * @return String
   */
  public String getUpload() {
    return amoData.getUpload();
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
    try {
      amoData = state.getObjectMapper().readValue(input, Amo.class);
    } catch (IOException exc) {
      return;
    }

    if ((amoData.getMsg() == null)
        || (amoData.getRemoteAddressChain() == null)
        || (amoData.getUid() == null)) {
      return;
    }

    // AMO can send log messages with the remote address field set to an empty string,
    // if this happens just stop here and don't classify the event. Also set the value in
    // the data set to null.
    if (amoData.getRemoteAddressChain().isEmpty()) {
      amoData.setRemoteAddressChain(null);
      return;
    }

    // Set source address; pass null for the normalized component since we don't want to
    // set the fields in there for this event type
    setSourceAddress(amoData.getRemoteAddressChain(), state, null);

    Matcher mat = Pattern.compile(reLogin).matcher(amoData.getMsg());
    if (mat.matches()) {
      type = EventType.LOGIN;
      // UID field will not be set in this case, so override from the msg
      amoData.setUid(mat.group(1));
      // XXX We could set normalized authentication fields here, but for now just leave
      // this out.
      return;
    }

    mat = Pattern.compile(reNewVersion).matcher(amoData.getMsg());
    if (mat.matches()) {
      type = EventType.NEWVERSION;
      addonVersion = mat.group(1);
      addonId = mat.group(2);
      return;
    }

    mat = Pattern.compile(reFxaLogin).matcher(amoData.getMsg());
    if (mat.matches()) {
      type = EventType.FXALOGIN;
      // Prefer the email field over the parsed value, but if it is unset then just grab
      // it here
      if (amoData.getEmail() == null) {
        amoData.setEmail(mat.group(1));
      }
      return;
    }

    mat = Pattern.compile(reFileUpload).matcher(amoData.getMsg());
    if (mat.matches()) {
      type = EventType.FILEUPLOAD;
      return;
    }

    mat = Pattern.compile(reRestricted).matcher(amoData.getMsg());
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

    mat = Pattern.compile(reFileUploadMnt).matcher(amoData.getMsg());
    if (mat.matches()) {
      type = EventType.FILEUPLOADMNT;
      fileName = mat.group(1);
      bytes = new Integer(mat.group(2));
      return;
    }
  }
}
