package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;

/** Payload parser for FxA authentication server log data */
public class FxaAuth extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Event summary is determined based on source event fields */
  public enum EventSummary {
    LOGIN_FAILURE {
      @Override
      public String toString() {
        return "loginFailure";
      }
    },
    ACCOUNT_STATUS_CHECK_SUCCESS {
      @Override
      public String toString() {
        return "accountStatusCheckSuccess";
      }
    },
    RECOVERY_EMAIL_VERIFY_CODE_FAILURE {
      @Override
      public String toString() {
        return "recoveryEmailVerifyCodeFailure";
      }
    },
    SEND_RECOVERY_EMAIL_SUCCESS {
      @Override
      public String toString() {
        return "sendRecoveryEmailSuccess";
      }
    },
    SEND_SMS_CONNECT_DEVICE_SUCCESS {
      @Override
      public String toString() {
        return "sendSmsConnectDeviceSuccess";
      }
    },
    ACCOUNT_CREATE_SUCCESS {
      @Override
      public String toString() {
        return "accountCreateSuccess";
      }
    },
    LOGIN_SUCCESS {
      @Override
      public String toString() {
        return "loginSuccess";
      }
    },
    DEVICES_LIST_SUCCESS {
      @Override
      public String toString() {
        return "devicesListSuccess";
      }
    },
    PASSWORD_FORGOT_SEND_CODE_SUCCESS {
      @Override
      public String toString() {
        return "passwordForgotSendCodeSuccess";
      }
    },
    PASSWORD_FORGOT_SEND_CODE_FAILURE {
      @Override
      public String toString() {
        return "passwordForgotSendCodeFailure";
      }
    },
    CERTIFICATE_SIGN_SUCCESS {
      @Override
      public String toString() {
        return "certificateSignSuccess";
      }
    }
  }

  private com.mozilla.secops.parser.models.fxaauth.FxaAuth fxaAuthData;
  private EventSummary eventSummary;

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

  private ObjectMapper getObjectMapper(ParserState state) {
    return state.getObjectMapper();
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    ObjectMapper mapper = getObjectMapper(state);
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

  private Boolean discernLoginSuccess() {
    if (!fxaAuthData.getPath().equals("/v1/account/login")) {
      return false;
    }
    if (!fxaAuthData.getStatus().equals(200)) {
      return false;
    }
    if (!fxaAuthData.getMethod().toLowerCase().equals("post")) {
      return false;
    }

    eventSummary = EventSummary.LOGIN_SUCCESS;
    return true;
  }

  private Boolean discernStatusCheck() {
    if (!fxaAuthData.getPath().equals("/v1/account/status")) {
      return false;
    }
    if (!fxaAuthData.getStatus().equals(200)) {
      return false;
    }
    if (!((fxaAuthData.getMethod().toLowerCase().equals("post"))
        || (fxaAuthData.getMethod().toLowerCase().equals("get")))) {
      return false;
    }
    eventSummary = EventSummary.ACCOUNT_STATUS_CHECK_SUCCESS;
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
    eventSummary = EventSummary.SEND_RECOVERY_EMAIL_SUCCESS;
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
    eventSummary = EventSummary.SEND_SMS_CONNECT_DEVICE_SUCCESS;
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
    eventSummary = EventSummary.ACCOUNT_CREATE_SUCCESS;
    return true;
  }

  private Boolean discernDevicesList() {
    if (!(fxaAuthData.getPath().equals("/v1/account/devices"))) {
      return false;
    }
    if (!(fxaAuthData.getStatus().equals(200))) {
      return false;
    }
    if (!(fxaAuthData.getMethod().toLowerCase().equals("get"))) {
      return false;
    }
    eventSummary = EventSummary.DEVICES_LIST_SUCCESS;
    return true;
  }

  private Boolean discernPasswordForgotSendCode() {
    if (!(fxaAuthData.getPath().equals("/v1/password/forgot/send_code"))) {
      return false;
    }
    if (!(fxaAuthData.getMethod().toLowerCase().equals("post"))) {
      return false;
    }
    if (fxaAuthData.getStatus().equals(200)) {
      eventSummary = EventSummary.PASSWORD_FORGOT_SEND_CODE_SUCCESS;
      return true;
    } else if (fxaAuthData.getStatus().equals(400)) {
      eventSummary = EventSummary.PASSWORD_FORGOT_SEND_CODE_FAILURE;
      return true;
    }
    return false;
  }

  public Boolean discernCertificateSignSuccess() {
    if (!(fxaAuthData.getPath().equals("/v1/certificate/sign"))) {
      return false;
    }
    if (!(fxaAuthData.getMethod().toLowerCase().equals("post"))) {
      return false;
    }
    if (fxaAuthData.getStatus().equals(200)) {
      eventSummary = EventSummary.CERTIFICATE_SIGN_SUCCESS;
      return true;
    }
    return false;
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
    } else if (discernLoginSuccess()) {
      return;
    } else if (discernPasswordForgotSendCode()) {
      return;
    } else if (discernCertificateSignSuccess()) {
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
    ObjectMapper mapper = getObjectMapper(state);
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
          String sa = state.getParser().applyXffAddressSelector(String.join(",", raca));
          if (sa != null) {
            setSourceAddress(sa, state, null);
          }
        }
      } catch (IOException exc) {
        // pass
      }
    }

    discernEventSummary();
  }
}
