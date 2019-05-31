package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.maxmind.geoip2.model.CityResponse;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Payload parser for AMO docker logs */
public class AmoDocker extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String reLogin = "^User \\(\\d+: (\\S+)\\) logged in successfully";

  public enum EventType {
    /** Login event */
    LOGIN
  }

  private String msg;
  private String remoteIp;
  private String remoteIpCity;
  private String remoteIpCountry;
  private String uid;

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

  private Map<String, String> convertInput(String input) {
    ObjectMapper mapper = new ObjectMapper();
    Map<String, String> fields = new HashMap<String, String>();
    try {
      fields = mapper.readValue(input, new TypeReference<Map<String, String>>() {});
    } catch (IOException exc) {
      return null;
    }
    return fields;
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
    Map<String, String> fields = convertInput(input);
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
  }
}
