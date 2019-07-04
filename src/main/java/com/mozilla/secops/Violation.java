package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.alert.Alert;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
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
    /** HTTP request threshold violation */
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
    USERAGENT_BLACKLIST_VIOLATION {
      @Override
      public String toString() {
        return "useragent_blacklist_violation";
      }
    },
    ABUSIVE_ACCOUNT_VIOLATION {
      @Override
      public String toString() {
        return "abusive_account_violation";
      }
    }
  }

  private static final Map<String, ViolationType> violationMap;

  /*
   * Maps metadata category values as would be specified in HTTPRequest to actual
   * violation types used in violations
   */
  static {
    Map<String, ViolationType> tMap = new HashMap<>();
    tMap.put("error_rate", ViolationType.CLIENT_ERROR_RATE_VIOLATION);
    tMap.put("threshold_analysis", ViolationType.REQUEST_THRESHOLD_VIOLATION);
    tMap.put("endpoint_abuse", ViolationType.ENDPOINT_ABUSE_VIOLATION);
    tMap.put("hard_limit", ViolationType.HARD_LIMIT_VIOLATION);
    tMap.put("useragent_blacklist", ViolationType.USERAGENT_BLACKLIST_VIOLATION);
    tMap.put("account_creation_abuse", ViolationType.ABUSIVE_ACCOUNT_VIOLATION);
    // XXX Just reuse ENDPOINT_ABUSE_VIOLATION here for specific Amo pipeline alerts.
    // These should eventually be moved to a dedicated violation type.
    tMap.put("fxa_account_abuse_new_version_login", ViolationType.ENDPOINT_ABUSE_VIOLATION);
    tMap.put("fxa_account_abuse_new_version_submission", ViolationType.ENDPOINT_ABUSE_VIOLATION);
    violationMap = Collections.unmodifiableMap(tMap);
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
    String categoryField = null;
    if (a.getCategory().equals("httprequest")) {
      categoryField = "category";
    } else if (a.getCategory().equals("customs")) {
      categoryField = "customs_category";
    } else if (a.getCategory().equals("amo")) {
      categoryField = "amo_category";
    } else {
      return null;
    }

    String aType = a.getMetadataValue(categoryField);
    if (aType == null) {
      return null;
    }
    ViolationType vt = violationMap.get(aType);
    if (vt == null) {
      return null;
    }
    ArrayList<Violation> ret = new ArrayList<>();
    ArrayList<String> vObj = new ArrayList<>();
    ArrayList<String> vType = new ArrayList<>();
    switch (vt) {
      case CLIENT_ERROR_RATE_VIOLATION:
      case REQUEST_THRESHOLD_VIOLATION:
      case ENDPOINT_ABUSE_VIOLATION:
      case HARD_LIMIT_VIOLATION:
      case USERAGENT_BLACKLIST_VIOLATION:
        if (a.getMetadataValue("sourceaddress") == null) {
          return null;
        }
        vObj.add(a.getMetadataValue("sourceaddress"));
        vType.add("ip");
        break;
      case ABUSIVE_ACCOUNT_VIOLATION:
        if (a.getMetadataValue("email") == null) {
          return null;
        }
        String[] parts = a.getMetadataValue("email").split(", ?");
        for (String i : parts) {
          vObj.add(i);
          vType.add("email");
        }
        break;
      default:
        return null;
    }

    if (vObj.size() != vType.size()) {
      throw new RuntimeException("violation object and type count mismatch");
    }
    String suppressValue = a.getMetadataValue(IprepdIO.IPREPD_SUPPRESS_RECOVERY);
    for (int i = 0; i < vObj.size(); i++) {
      if (suppressValue != null) {
        ret.add(
            new Violation(vObj.get(i), vType.get(i), vt.toString(), new Integer(suppressValue)));
      } else {
        ret.add(new Violation(vObj.get(i), vType.get(i), vt.toString()));
      }
    }
    return ret.toArray(new Violation[vObj.size()]);
  }
}
