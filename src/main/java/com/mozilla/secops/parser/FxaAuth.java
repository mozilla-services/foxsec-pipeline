package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.maxmind.geoip2.model.CityResponse;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;

/** Payload parser for FxA authentication server log data */
public class FxaAuth extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Event summary is determined based on source event fields */
  public enum EventSummary {
    LOGIN_FAILURE {
      @Override
      public String toString() {
        return "loginFailure";
      }
    },
    ACCOUNT_STATUS_CHECK {
      @Override
      public String toString() {
        return "accountStatusCheck";
      }
    },
    RECOVERY_EMAIL_VERIFY_CODE_FAILURE {
      @Override
      public String toString() {
        return "recoveryEmailVerifyCodeFailure";
      }
    },
    SEND_RECOVERY_EMAIL {
      @Override
      public String toString() {
        return "sendRecoveryEmail";
      }
    },
    SEND_SMS_CONNECT_DEVICE {
      @Override
      public String toString() {
        return "sendSmsConnectDevice";
      }
    },
    ACCOUNT_CREATE {
      @Override
      public String toString() {
        return "accountCreate";
      }
    }
  }

  private com.mozilla.secops.parser.models.fxaauth.FxaAuth fxaAuthData;
  private EventSummary eventSummary;
  private String sourceAddress;
  private String sourceAddressCity;
  private String sourceAddressCountry;

  @Override
  public String eventStringValue(EventFilterPayload.StringProperty property) {
    switch (property) {
      case FXAAUTH_EVENTSUMMARY:
        if (eventSummary == null) {
          return null;
        } else {
          return eventSummary.toString();
        }
      case FXAAUTH_SOURCEADDRESS:
        return getSourceAddress();
      case FXAAUTH_ACCOUNTID:
        if (fxaAuthData == null) {
          return null;
        }
        return fxaAuthData.getEmail();
      case FXAAUTH_UID:
        if (fxaAuthData == null) {
          return null;
        }
        return fxaAuthData.getUid();
    }
    return null;
  }

  private ObjectMapper getObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
    return mapper;
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    ObjectMapper mapper = getObjectMapper();
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d;
    try {
      d = mapper.readValue(input, com.mozilla.secops.parser.models.fxaauth.FxaAuth.class);
    } catch (IOException exc) {
      return false;
    }
    Mozlog m = state.getMozlogHint();
    if (m == null) {
      return false;
    }
    String logger = m.getLogger();
    if (logger == null) {
      return false;
    }
    if (logger.equals("fxa-auth-server")) {
      return true;
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.FXAAUTH;
  }

  /**
   * Fetch parsed FxA auth data
   *
   * @return FxA auth data
   */
  @JsonProperty("fxaauth_data")
  public com.mozilla.secops.parser.models.fxaauth.FxaAuth getFxaAuthData() {
    return fxaAuthData;
  }

  /**
   * Get event summary
   *
   * @return Event summary
   */
  @JsonProperty("event_summary")
  public EventSummary getEventSummary() {
    return eventSummary;
  }

  /**
   * Get client source address
   *
   * @return String
   */
  @JsonProperty("sourceaddress")
  public String getSourceAddress() {
    return sourceAddress;
  }

  /**
   * Get source address city
   *
   * @return String
   */
  @JsonProperty("sourceaddress_city")
  public String getSourceAddressCity() {
    return sourceAddressCity;
  }

  /**
   * Get source address country
   *
   * @return String
   */
  @JsonProperty("sourceaddress_country")
  public String getSourceAddressCountry() {
    return sourceAddressCountry;
  }

  private Boolean discernLoginFailure() {
    if (!fxaAuthData.getPath().equals("/v1/account/login")) {
      return false;
    }
    if (!fxaAuthData.getStatus().equals(400)) {
      return false;
    }

    // Confirm we have specific errno values here related to credential verification
    // before we classify the event, we don't want to include other types or errors
    if (fxaAuthData.getErrno() == null) {
      return false;
    }

    if ((fxaAuthData.getErrno()
            != com.mozilla.secops.parser.models.fxaauth.FxaAuth.Errno.INCORRECT_PASSWORD)
        && (fxaAuthData.getErrno()
            != com.mozilla.secops.parser.models.fxaauth.FxaAuth.Errno.ACCOUNT_UNKNOWN)) {
      return false;
    }

    eventSummary = EventSummary.LOGIN_FAILURE;
    return true;
  }

  private Boolean discernStatusCheck() {
    if (!fxaAuthData.getPath().equals("/v1/account/status")) {
      return false;
    }
    if (!fxaAuthData.getStatus().equals(200)) {
      return false;
    }
    if (!fxaAuthData.getMethod().toLowerCase().equals("post")) {
      return false;
    }
    eventSummary = EventSummary.ACCOUNT_STATUS_CHECK;
    return true;
  }

  private Boolean discernRecoveryEmailVerifyCodeFailure() {
    if (!fxaAuthData.getPath().equals("/v1/recovery_email/verify_code")) {
      return false;
    }
    if (!fxaAuthData.getStatus().equals(400)) {
      return false;
    }
    if (!fxaAuthData.getMethod().toLowerCase().equals("post")) {
      return false;
    }

    if ((fxaAuthData.getErrno()
            != com.mozilla.secops.parser.models.fxaauth.FxaAuth.Errno.INVALID_VERIFICATION_CODE)
        && (fxaAuthData.getErrno()
            != com.mozilla.secops.parser.models.fxaauth.FxaAuth.Errno.ACCOUNT_UNKNOWN)) {
      return false;
    }

    eventSummary = EventSummary.RECOVERY_EMAIL_VERIFY_CODE_FAILURE;
    return true;
  }

  private Boolean discernSendRecoveryEmail() {
    if (!fxaAuthData.getPath().equals("/v1/recovery_email")) {
      return false;
    }
    if (!fxaAuthData.getStatus().equals(200)) {
      return false;
    }
    if (!fxaAuthData.getMethod().toLowerCase().equals("post")) {
      return false;
    }
    eventSummary = EventSummary.SEND_RECOVERY_EMAIL;
    return true;
  }

  private Boolean discernSendSmsConnectDevice() {
    if (!fxaAuthData.getPath().equals("/v1/sms")) {
      return false;
    }
    if (!fxaAuthData.getStatus().equals(200)) {
      return false;
    }
    if (!fxaAuthData.getMethod().toLowerCase().equals("post")) {
      return false;
    }
    eventSummary = EventSummary.SEND_SMS_CONNECT_DEVICE;
    return true;
  }

  private Boolean discernAccountCreate() {
    if (!(fxaAuthData.getPath().equals("/v1/account/create"))) {
      return false;
    }
    if (!(fxaAuthData.getStatus().equals(200))) {
      return false;
    }
    if (!(fxaAuthData.getMethod().toLowerCase().equals("post"))) {
      return false;
    }
    eventSummary = EventSummary.ACCOUNT_CREATE;
    return true;
  }

  private void discernEventSummary() {
    if (fxaAuthData.getPath() == null) {
      return;
    }
    if (fxaAuthData.getMethod() == null) {
      return;
    }
    if (fxaAuthData.getStatus() == null) {
      return;
    }

    // If the request was already blocked, don't classify the event since the request
    // would already have been rejected.
    if ((fxaAuthData.getErrno() != null)
        && (fxaAuthData.getErrno()
            == com.mozilla.secops.parser.models.fxaauth.FxaAuth.Errno.REQUEST_BLOCKED)) {
      return;
    }

    if (discernLoginFailure()) {
      return;
    } else if (discernStatusCheck()) {
      return;
    } else if (discernRecoveryEmailVerifyCodeFailure()) {
      return;
    } else if (discernSendRecoveryEmail()) {
      return;
    } else if (discernSendSmsConnectDevice()) {
      return;
    } else if (discernAccountCreate()) {
      return;
    }
  }

  /** Construct matcher object. */
  public FxaAuth() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public FxaAuth(String input, Event e, ParserState state) {
    ObjectMapper mapper = getObjectMapper();
    try {
      fxaAuthData = mapper.readValue(input, com.mozilla.secops.parser.models.fxaauth.FxaAuth.class);
      if (fxaAuthData == null) {
        return;
      }
    } catch (IOException exc) {
      return;
    }

    String rac = fxaAuthData.getRemoteAddressChain();
    if (rac != null) {
      // The auth server source address information is stored as a JSON encoded string that is an
      // array of addresses, so convert that
      ArrayList<String> raca = new ArrayList<>();
      try {
        raca =
            mapper.readValue(
                rac,
                mapper.getTypeFactory().constructCollectionType(ArrayList.class, String.class));
        if (raca != null) {
          sourceAddress = state.getParser().applyXffAddressSelector(String.join(",", raca));
        }
      } catch (IOException exc) {
        // pass
      }
    }

    if (sourceAddress != null) {
      CityResponse cr = state.getParser().geoIp(sourceAddress);
      if (cr != null) {
        sourceAddressCity = cr.getCity().getName();
        sourceAddressCountry = cr.getCountry().getIsoCode();
      }
    }

    discernEventSummary();
  }
}
