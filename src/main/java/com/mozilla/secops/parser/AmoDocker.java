package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.maxmind.geoip2.model.CityResponse;
import java.io.Serializable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Payload parser for AMO docker logs */
public class AmoDocker extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String reLogin = "^User \\(\\d+: (\\S+)\\) logged in successfully";
  private final String reNewVersion =
      "^New version: <Version: ([^>]+)> \\((\\d+)\\) from <FileUpload: [^>]+>";
  private final String reGotProfile = "^Got profile.*'email': ?'([^']+)'.*";
  private final String reFileUpload = "^FileUpload created: \\S+$";

  public enum EventType {
    /** Login event */
    LOGIN,
    /** New addon upload */
    NEWVERSION,
    /** FxA profile fetch */
    GOTPROFILE,
    /** File upload */
    FILEUPLOAD
  }

  private String msg;
  private String remoteIp;
  private String remoteIpCity;
  private String remoteIpCountry;
  private String uid;
  private String fxaEmail;

  private String addonVersion;
  private String addonId;

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
    return remoteIp;
  }

  /**
   * Get UID
   *
   * @return String
   */
  public String getUid() {
    return uid;
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    // There should always have an associated Mozlog hint
    Mozlog hint = state.getMozlogHint();
    if (hint == null) {
      return false;
    }
    String logger = hint.getLogger();
    if ((logger != null) && (logger.equals("http_app_addons"))) {
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
    remoteIp = fields.get("remoteAddressChain");
    uid = fields.get("uid");

    if ((msg == null) || (remoteIp == null) || (uid == null)) {
      return;
    }

    if (remoteIp != null) {
      CityResponse cr = state.getParser().geoIp(remoteIp);
      if (cr != null) {
        remoteIpCity = cr.getCity().getName();
        remoteIpCountry = cr.getCountry().getIsoCode();
      }
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
      fxaEmail = mat.group(1);
      return;
    }

    mat = Pattern.compile(reFileUpload).matcher(msg);
    if (mat.matches()) {
      type = EventType.FILEUPLOAD;
      return;
    }
  }
}
