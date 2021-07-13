package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a violation as would be submitted to iprepd
 *
 * <p>See <a href="https://github.com/mozilla-services/iprepd">iprepd</a>
 */
@JsonInclude(Include.NON_NULL)
public class Violation {
  private final String object;
  private final String type;
  private final String violation;
  private Integer suppressRecovery;

  /** Valid violation types */
  public enum ViolationType {
    REQUEST_THRESHOLD_VIOLATION {
      @Override
      public String toString() {
        return "request_threshold_violation";
      }
    },
    CLIENT_ERROR_RATE_VIOLATION {
      @Override
      public String toString() {
        return "client_error_rate_violation";
      }
    },
    ENDPOINT_ABUSE_VIOLATION {
      @Override
      public String toString() {
        return "endpoint_abuse_violation";
      }
    },
    HARD_LIMIT_VIOLATION {
      @Override
      public String toString() {
        return "hard_limit_violation";
      }
    },
    USERAGENT_BLOCKLIST_VIOLATION {
      @Override
      public String toString() {
        return "violation20";
      }
    },
    ABUSIVE_ACCOUNT_VIOLATION {
      @Override
      public String toString() {
        return "abusive_account_violation";
      }
    },
    PER_ENDPOINT_ERROR_RATE_VIOLATION {
      @Override
      public String toString() {
        return "violation75";
      }
    },
    STATUS_CODE_RATE_VIOLATION {
      @Override
      public String toString() {
        return "violation20";
      }
    },
    SESSION_LIMIT_VIOLATION {
      @Override
      public String toString() {
        return "violation20";
      }
    }
  }

  private abstract static class ViolationGenerator {
    public abstract Violation[] generate(Alert a);

    protected Violation createViolation(Alert a, String object, String type, String vStr) {
      String suppressValue = a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY);
      if (suppressValue == null) {
        return new Violation(object, type, vStr);
      } else {
        return new Violation(object, type, vStr, new Integer(suppressValue));
      }
    }
  }

  private static class GenericSourceViolationGenerator extends ViolationGenerator {
    private ViolationType vType;

    public Violation[] generate(Alert a) {
      ArrayList<Violation> ret = new ArrayList<>();
      if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS) == null) {
        return null;
      }
      ret.add(
          createViolation(
              a, a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS), "ip", vType.toString()));
      return ret.toArray(new Violation[ret.size()]);
    }

    public GenericSourceViolationGenerator(ViolationType vType) {
      this.vType = vType;
    }
  }

  private static class EmailListViolationGenerator extends ViolationGenerator {
    private ViolationType vType;

    public Violation[] generate(Alert a) {
      ArrayList<Violation> ret = new ArrayList<>();
      String emails = a.getMetadataValue(AlertMeta.Key.EMAIL);
      if (emails == null) {
        return null;
      }
      List<String> parts = null;
      try {
        parts = AlertMeta.splitListValues(AlertMeta.Key.EMAIL, emails);
      } catch (IOException exc) {
        return null;
      }
      for (String i : parts) {
        ret.add(createViolation(a, i, "email", vType.toString()));
      }
      return ret.toArray(new Violation[ret.size()]);
    }

    public EmailListViolationGenerator(ViolationType vType) {
      this.vType = vType;
    }
  }

  private static class MatchedAddonCustomViolationGenerator extends ViolationGenerator {
    public Violation[] generate(Alert a) {
      // Custom generator implementation; we will create a violation both for the email
      // address if present and the source address.
      ArrayList<Violation> ret = new ArrayList<>();
      if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS) == null) {
        return null;
      }
      ret.add(
          createViolation(
              a,
              a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS),
              "ip",
              ViolationType.ENDPOINT_ABUSE_VIOLATION.toString()));
      if (a.getMetadataValue(AlertMeta.Key.EMAIL) != null) {
        List<String> parts = null;
        try {
          parts =
              AlertMeta.splitListValues(
                  AlertMeta.Key.EMAIL, a.getMetadataValue(AlertMeta.Key.EMAIL));
        } catch (IOException exc) {
          return null;
        }
        for (String i : parts) {
          ret.add(
              createViolation(a, i, "email", ViolationType.ABUSIVE_ACCOUNT_VIOLATION.toString()));
        }
      }
      return ret.toArray(new Violation[ret.size()]);
    }
  }

  private static final Map<String, ViolationGenerator> generatorMap;

  static {
    Map<String, ViolationGenerator> vMap = new HashMap<>();

    // HTTPRequest
    vMap.put(
        "error_rate",
        new GenericSourceViolationGenerator(ViolationType.CLIENT_ERROR_RATE_VIOLATION));
    vMap.put(
        "threshold_analysis",
        new GenericSourceViolationGenerator(ViolationType.REQUEST_THRESHOLD_VIOLATION));
    vMap.put(
        "endpoint_abuse",
        new GenericSourceViolationGenerator(ViolationType.ENDPOINT_ABUSE_VIOLATION));
    vMap.put(
        "useragent_blocklist",
        new GenericSourceViolationGenerator(ViolationType.USERAGENT_BLOCKLIST_VIOLATION));
    vMap.put("hard_limit", new GenericSourceViolationGenerator(ViolationType.HARD_LIMIT_VIOLATION));
    vMap.put(
        "per_endpoint_error_rate",
        new GenericSourceViolationGenerator(ViolationType.PER_ENDPOINT_ERROR_RATE_VIOLATION));
    vMap.put(
        "status_code_rate_analysis",
        new GenericSourceViolationGenerator(ViolationType.STATUS_CODE_RATE_VIOLATION));
    vMap.put(
        "session_limit_analysis",
        new GenericSourceViolationGenerator(ViolationType.SESSION_LIMIT_VIOLATION));

    // Customs
    vMap.put(
        "account_creation_abuse",
        new EmailListViolationGenerator(ViolationType.ABUSIVE_ACCOUNT_VIOLATION));

    // AMO
    vMap.put(
        "fxa_account_abuse_new_version_login",
        new GenericSourceViolationGenerator(ViolationType.ENDPOINT_ABUSE_VIOLATION));
    vMap.put(
        "fxa_account_abuse_new_version_submission",
        new GenericSourceViolationGenerator(ViolationType.ENDPOINT_ABUSE_VIOLATION));
    vMap.put(
        "fxa_account_abuse_new_version_login_banpattern",
        new EmailListViolationGenerator(ViolationType.ABUSIVE_ACCOUNT_VIOLATION));
    vMap.put(
        "fxa_account_abuse_alias",
        new EmailListViolationGenerator(ViolationType.ABUSIVE_ACCOUNT_VIOLATION));
    vMap.put("amo_abuse_matched_addon", new MatchedAddonCustomViolationGenerator());
    vMap.put(
        "amo_abuse_multi_match",
        new EmailListViolationGenerator(ViolationType.ABUSIVE_ACCOUNT_VIOLATION));
    vMap.put(
        "amo_abuse_multi_submit",
        new EmailListViolationGenerator(ViolationType.ABUSIVE_ACCOUNT_VIOLATION));
    vMap.put(
        "amo_abuse_multi_ip_login",
        new EmailListViolationGenerator(ViolationType.ABUSIVE_ACCOUNT_VIOLATION));

    generatorMap = Collections.unmodifiableMap(vMap);
  }

  /**
   * Create new {@link Violation}
   *
   * @param object Object identifier
   * @param type Object type
   * @param violation ViolationType as string
   */
  public Violation(String object, String type, String violation) {
    this.object = object;
    this.type = type;
    this.violation = violation;
  }

  /**
   * Create new {@link Violation} with recovery suppression value
   *
   * @param object Object name
   * @param type Type
   * @param violation ViolationType as string
   * @param suppressRecovery Recovery suppression value in seconds
   */
  public Violation(String object, String type, String violation, Integer suppressRecovery) {
    this(object, type, violation);
    this.suppressRecovery = suppressRecovery;
  }

  /**
   * Get object
   *
   * @return Object string
   */
  @JsonProperty("object")
  public String getObject() {
    return object;
  }

  /**
   * Get object type
   *
   * @return Object type string
   */
  @JsonProperty("type")
  public String getType() {
    return type;
  }

  /**
   * Get source address
   *
   * <p>This is a legacy field that maintains compatibility with older versions of iprepd. If the
   * type is of type "ip", this function will simply return the same value as the object in the
   * violation.
   *
   * <p>For other types, null is returned.
   *
   * @return Source address string
   */
  @JsonProperty("ip")
  public String getSourceAddress() {
    if (type.equals("ip")) {
      return object;
    }
    return null;
  }

  /**
   * Get violation type
   *
   * @return Violation type string
   */
  @JsonProperty("violation")
  public String getViolation() {
    return violation;
  }

  @JsonProperty("suppress_recovery")
  public Integer getSuppressRecovery() {
    return suppressRecovery;
  }

  /**
   * Convert {@link Violation} to JSON string
   *
   * @return Violation JSON string or null on serialization failure
   */
  public String toJSON() {
    ObjectMapper mapper = new ObjectMapper();
    try {
      return mapper.writeValueAsString(this);
    } catch (JsonProcessingException exc) {
      return null;
    }
  }

  /**
   * Convert an {@link Alert} into violations
   *
   * <p>The alert must be of the correct type (e.g., generated by HTTPRequest) and have valid
   * associated metadata in order for conversion to be successful.
   *
   * <p>An array of resulting violations is returned. In most cases the array will have a single
   * element, but some alerts can result in multiple violations being generated.
   *
   * @param a Alert
   * @return Array of violations or null if conversion is not possible
   */
  public static Violation[] fromAlert(Alert a) {
    String aType = a.getSubcategory();
    if (aType == null) {
      return null;
    }
    ViolationGenerator vg = generatorMap.get(aType);
    if (vg == null) {
      return null;
    }
    return vg.generate(a);
  }
}
