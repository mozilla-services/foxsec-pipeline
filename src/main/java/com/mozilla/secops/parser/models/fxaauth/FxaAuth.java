package com.mozilla.secops.parser.models.fxaauth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import java.io.Serializable;

/** FxA authentication server event */
@JsonIgnoreProperties(ignoreUnknown = true)
public class FxaAuth implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * FxA error values
   *
   * <p>See also https://github.com/mozilla/fxa-auth-server/blob/master/lib/error.js
   */
  public enum Errno {
    SERVER_CONFIG_ERROR(100),
    ACCOUNT_EXISTS(101),
    ACCOUNT_UNKNOWN(102),
    INCORRECT_PASSWORD(103),
    ACCOUNT_UNVERIFIED(104),
    INVALID_VERIFICATION_CODE(105),
    INVALID_JSON(106),
    INVALID_PARAMETER(107),
    MISSING_PARAMETER(108),
    INVALID_REQUEST_SIGNATURE(109),
    INVALID_TOKEN(110),
    INVALID_TIMESTAMP(111),
    MISSING_CONTENT_LENGTH_HEADER(112),
    REQUEST_TOO_LARGE(113),
    THROTTLED(114),
    INVALID_NONCE(115),
    ENDPOINT_NOT_SUPPORTED(116),
    INCORRECT_EMAIL_CASE(120),
    // ACCOUNT_LOCKED(121),
    // ACCOUNT_NOT_LOCKED(122),
    DEVICE_UNKNOWN(123),
    DEVICE_CONFLICT(124),
    REQUEST_BLOCKED(125),
    ACCOUNT_RESET(126),
    INVALID_UNBLOCK_CODE(127),
    // MISSING_TOKEN(128),
    INVALID_PHONE_NUMBER(129),
    INVALID_REGION(130),
    INVALID_MESSAGE_ID(131),
    MESSAGE_REJECTED(132),
    BOUNCE_COMPLAINT(133),
    BOUNCE_HARD(134),
    BOUNCE_SOFT(135),
    EMAIL_EXISTS(136),
    EMAIL_DELETE_PRIMARY(137),
    SESSION_UNVERIFIED(138),
    USER_PRIMARY_EMAIL_EXISTS(139),
    VERIFIED_PRIMARY_EMAIL_EXISTS(140),
    // If there exists an account that was created under 24hrs and
    // has not verified their email address, this error is thrown
    // if another user attempts to add that email to their account
    // as a secondary email.
    UNVERIFIED_PRIMARY_EMAIL_NEWLY_CREATED(141),
    LOGIN_WITH_SECONDARY_EMAIL(142),
    SECONDARY_EMAIL_UNKNOWN(143),
    VERIFIED_SECONDARY_EMAIL_EXISTS(144),
    RESET_PASSWORD_WITH_SECONDARY_EMAIL(145),
    INVALID_SIGNIN_CODE(146),
    CHANGE_EMAIL_TO_UNVERIFIED_EMAIL(147),
    CHANGE_EMAIL_TO_UNOWNED_EMAIL(148),
    LOGIN_WITH_INVALID_EMAIL(149),
    RESEND_EMAIL_CODE_TO_UNOWNED_EMAIL(150),
    FAILED_TO_SEND_EMAIL(151),
    INVALID_TOKEN_VERIFICATION_CODE(152),
    EXPIRED_TOKEN_VERIFICATION_CODE(153),
    TOTP_TOKEN_EXISTS(154),
    TOTP_TOKEN_NOT_FOUND(155),
    RECOVERY_CODE_NOT_FOUND(156),
    DEVICE_COMMAND_UNAVAILABLE(157),
    RECOVERY_KEY_NOT_FOUND(158),
    RECOVERY_KEY_INVALID(159),
    TOTP_REQUIRED(160),
    RECOVERY_KEY_EXISTS(161),
    UNKNOWN_CLIENT_ID(162),
    STALE_AUTH_AT(164),
    SERVER_BUSY(201),
    FEATURE_NOT_ENABLED(202),
    BACKEND_SERVICE_FAILURE(203),
    INTERNAL_VALIDATION_ERROR(998),
    UNEXPECTED_ERROR(999);

    private int value;

    /**
     * Return integer value of enum
     *
     * @return int
     */
    @JsonValue
    public int getValue() {
      return value;
    }

    @JsonCreator
    public static Errno forValue(int errno) {
      for (Errno e : values()) {
        if (e.getValue() == errno) {
          return e;
        }
      }
      return null;
    }

    private Errno(int value) {
      this.value = value;
    }
  }

  private String agent;
  private String email;
  private Errno errno;
  private Boolean keys;
  private String lang;
  private String method;
  private String op;
  private String path;
  private String remoteAddressChain;
  private String service;
  private Integer status;
  private Integer t;
  private String uid;

  /**
   * Get agent
   *
   * @return String
   */
  @JsonProperty("agent")
  public String getAgent() {
    return agent;
  }

  /**
   * Get email
   *
   * @return String
   */
  @JsonProperty("email")
  public String getEmail() {
    return email;
  }

  public String getSmsRecipient() {
    return null;
  }

  /**
   * Get errno
   *
   * @return Errno
   */
  @JsonProperty("errno")
  public Errno getErrno() {
    return errno;
  }

  /**
   * Get keys
   *
   * @return Boolean
   */
  @JsonProperty("keys")
  public Boolean getKeys() {
    return keys;
  }

  /**
   * Get lang
   *
   * @return String
   */
  @JsonProperty("lang")
  public String getLang() {
    return lang;
  }

  /**
   * Get method
   *
   * @return String
   */
  @JsonProperty("method")
  public String getMethod() {
    return method;
  }

  /**
   * Get op
   *
   * @return String
   */
  @JsonProperty("op")
  public String getOp() {
    return op;
  }

  /**
   * Get path
   *
   * @return String
   */
  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  /**
   * Get remote address chain
   *
   * @return String
   */
  @JsonProperty("remoteAddressChain")
  public String getRemoteAddressChain() {
    return remoteAddressChain;
  }

  /**
   * Get service
   *
   * @return String
   */
  @JsonProperty("service")
  public String getService() {
    return service;
  }

  /**
   * Get status
   *
   * @return Integer
   */
  @JsonProperty("status")
  public Integer getStatus() {
    return status;
  }

  /**
   * Get t
   *
   * @return Integer
   */
  @JsonProperty("t")
  public Integer getT() {
    return t;
  }

  /**
   * Get uid
   *
   * @return String
   */
  @JsonProperty("uid")
  public String getUid() {
    return uid;
  }

  public FxaAuth() {}
}
