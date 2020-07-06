package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** Payload parser for Private Relay logs */
public class PrivateRelay extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Log event type */
  public enum EventType {
    /** Email relay */
    EMAIL_RELAY,
    /** FxA RP event */
    FXA_RP_EVENT
  }

  private String msg;
  private String uid;
  private String relayAddress;
  private String realAddress;
  private Integer relayAddressId;
  private EventType eventType;

  /**
   * Get msg
   *
   * @return String
   */
  public String getMsg() {
    return msg;
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
   * Get relay address
   *
   * @return String
   */
  public String getRelayAddress() {
    return relayAddress;
  }

  /**
   * Get real address
   *
   * @return String
   */
  public String getRealAddress() {
    return realAddress;
  }

  /**
   * Get event type
   *
   * @return EventType
   */
  public EventType getEventType() {
    return eventType;
  }

  /**
   * Get relay address ID
   *
   * @return int
   */
  public Integer getRelayAddressId() {
    return relayAddressId;
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    // There should always have an associated Mozlog hint
    Mozlog hint = state.getMozlogHint();
    if (hint == null) {
      return false;
    }
    String logger = hint.getLogger();
    if (logger == null) {
      return false;
    }
    if (logger.equals("fx-private-relay")) {
      return true;
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.PRIVATE_RELAY;
  }

  /** Construct matcher object. */
  public PrivateRelay() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public PrivateRelay(String input, Event e, ParserState state) {
    Mozlog hint = state.getMozlogHint();

    realAddress = (String) hint.getFields().get("real_address");
    relayAddress = (String) hint.getFields().get("relay_address");
    msg = (String) hint.getFields().get("msg");
    uid = (String) hint.getFields().get("fxa_uid");
    relayAddressId = (Integer) hint.getFields().get("relay_address_id");

    if (msg != null) {
      switch (msg) {
        case "email_relay":
          eventType = EventType.EMAIL_RELAY;
          break;
        case "fxa_rp_event":
          eventType = EventType.FXA_RP_EVENT;
          break;
      }
    }
  }
}
