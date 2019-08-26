package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.Map;

/** Payload parser for IPrepd logs */
public class IPrepdLog extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private String msg;
  private String violation;
  private String decayAfter;
  private Integer originalReputation;
  private Integer reputation;
  private String objectType;
  private String object;
  private Boolean exception;

  /**
   * Get msg
   *
   * @return String
   */
  public String getMsg() {
    return msg;
  }

  /**
   * Get violation
   *
   * @return String
   */
  public String getViolation() {
    return violation;
  }

  /**
   * Get decay after - time when reputation begins to heal
   *
   * @return String
   */
  public String getDecayAfter() {
    return decayAfter;
  }

  /**
   * Get the original reputation of the object the violation was applied to
   *
   * @return Integer
   */
  public Integer getOriginalReputation() {
    return originalReputation;
  }

  /**
   * Get the current reputation of the object the violation was applied to
   *
   * @return Integer
   */
  public Integer getReputation() {
    return reputation;
  }

  /**
   * Get object type (i.e. ip/email)
   *
   * @return String
   */
  public String getObjectType() {
    return objectType;
  }

  /**
   * Get whether an object is an exception or not
   *
   * @return Boolean
   */
  public Boolean getException() {
    return exception;
  }

  /**
   * Get the object (i.e. ip or email address)
   *
   * @return String
   */
  public String getObject() {
    return object;
  }

  @Override
  public Boolean matcher(String input, ParserState s) {
    Mozlog mlHint = s.getMozlogHint();
    if (mlHint == null) {
      return false;
    }
    if (!mlHint.getLogger().equals("iprepd")) {
      return false;
    }
    // at the moment we only pay attention to applied-violation event logs.
    // we reject all logs that do not conform to that type.
    Map<String, Object> fields = mlHint.getFields();
    return (fields != null
        && fields.containsKey("msg")
        && fields.containsKey("violation")
        && fields.containsKey("decay_after")
        && fields.containsKey("original_reputation")
        && fields.containsKey("reputation")
        && fields.containsKey("type")
        && fields.containsKey("exception")
        && fields.containsKey("object"));
  }

  public Payload.PayloadType getType() {
    return Payload.PayloadType.IPREPD_LOG;
  }

  /** Construct matcher object. */
  public IPrepdLog() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param s State
   */
  public IPrepdLog(String input, Event e, ParserState s) {
    Map<String, Object> fields = Parser.convertJsonToMap(input);
    if (fields == null) {
      return;
    }
    msg = (String) fields.get("msg");
    violation = (String) fields.get("violation");
    decayAfter = (String) fields.get("decay_after");
    originalReputation = (Integer) fields.get("original_reputation");
    reputation = (Integer) fields.get("reputation");
    objectType = (String) fields.get("type");
    exception = (Boolean) fields.get("exception");
    object = (String) fields.get("object");
  }
}
