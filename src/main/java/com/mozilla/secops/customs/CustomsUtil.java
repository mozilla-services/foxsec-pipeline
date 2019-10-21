package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.Payload;

/** Utility functions for working with {@link FxaAuth} events in customs */
public class CustomsUtil {
  /**
   * Extract FxA event payload
   *
   * @param e Event
   * @return FxaAuth payload, or null if not found
   */
  public static FxaAuth authGetPayload(Event e) {
    if (!(e.getPayloadType().equals(Payload.PayloadType.FXAAUTH))) {
      return null;
    }
    return e.getPayload();
  }

  /**
   * Extract FxA event internal data
   *
   * @param e Event
   * @return FxaAuth model data, or null if not found
   */
  public static com.mozilla.secops.parser.models.fxaauth.FxaAuth authGetData(Event e) {
    FxaAuth d = authGetPayload(e);
    return d != null ? d.getFxaAuthData() : null;
  }

  /**
   * Extract FxA event source address
   *
   * @param e Event
   * @return Address, or null if not found
   */
  public static String authGetSourceAddress(Event e) {
    FxaAuth d = authGetPayload(e);
    return d != null ? d.getSourceAddress() : null;
  }

  /**
   * Extract FxA event source address latitude
   *
   * @param e Event
   * @return Latitude, or null if not available
   */
  public static Double authGetSourceAddressLatitude(Event e) {
    FxaAuth d = authGetPayload(e);
    return d != null ? d.getSourceAddressLatitude() : null;
  }

  /**
   * Extract FxA event source address longitude
   *
   * @param e Event
   * @return Longitude, or null if not available
   */
  public static Double authGetSourceAddressLongitude(Event e) {
    FxaAuth d = authGetPayload(e);
    return d != null ? d.getSourceAddressLongitude() : null;
  }

  /**
   * Extract FxA event email address
   *
   * @param e Event
   * @return Address, or null if not found
   */
  public static String authGetEmail(Event e) {
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d = authGetData(e);
    return d != null ? d.getEmail() : null;
  }

  /**
   * Extract FxA event UID
   *
   * @param e Event
   * @return UID, or null if not found
   */
  public static String authGetUid(Event e) {
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d = authGetData(e);
    return d != null ? d.getUid() : null;
  }

  /**
   * Extract FxA event status code
   *
   * @param e Event
   * @return Status code, or null if not found
   */
  public static Integer authGetStatus(Event e) {
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d = authGetData(e);
    return d != null ? d.getStatus() : null;
  }

  /**
   * Extract FxA event path
   *
   * @param e Event
   * @return Path, or null if not found
   */
  public static String authGetPath(Event e) {
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d = authGetData(e);
    return d != null ? d.getPath() : null;
  }

  /**
   * Extract FxA agent
   *
   * @param e Event
   * @return Agent, or null if not found
   */
  public static String authGetUserAgent(Event e) {
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d = authGetData(e);
    return d != null ? d.getAgent() : null;
  }

  /**
   * Extract FxA event service value
   *
   * @param e Event
   * @return Service, or null if not found
   */
  public static String authGetService(Event e) {
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d = authGetData(e);
    return d != null ? d.getService() : null;
  }

  /**
   * Extract FxA event summary
   *
   * @param e Event
   * @return EventSummary value, or null if not found
   */
  public static FxaAuth.EventSummary authGetEventSummary(Event e) {
    FxaAuth d = authGetPayload(e);
    return d != null ? d.getEventSummary() : null;
  }
}
