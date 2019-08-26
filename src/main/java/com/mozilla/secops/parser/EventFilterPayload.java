package com.mozilla.secops.parser;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Can be associated with {@link EventFilterRule} for payload matching */
@JsonInclude(Include.NON_NULL)
@JsonDeserialize(as = EventFilterPayload.class)
public class EventFilterPayload implements EventFilterPayloadInterface, Serializable {
  private static final long serialVersionUID = 1L;

  /** Properties match strings from various payload event types */
  public enum StringProperty {
    NORMALIZED_SUBJECTUSER,
    NORMALIZED_REQUESTMETHOD,
    NORMALIZED_REQUESTURL,
    NORMALIZED_URLREQUESTPATH,
    NORMALIZED_URLREQUESTHOST,
    NORMALIZED_SOURCEADDRESS,

    SECEVENT_ACTION,
    SECEVENT_SOURCEADDRESS,
    SECEVENT_ACCOUNTID,
    SECEVENT_EMAILRECIPIENT,
    SECEVENT_SMSRECIPIENT,

    OPENSSH_AUTHMETHOD,

    RAW_RAW,

    CLOUDTRAIL_ACCOUNTID,
    CLOUDTRAIL_EVENTNAME,
    CLOUDTRAIL_EVENTSOURCE,
    CLOUDTRAIL_INVOKEDBY,
    CLOUDTRAIL_MFA,

    GLB_REQUESTMETHOD,
    GLB_URLREQUESTPATH,

    NGINX_REQUESTMETHOD,
    NGINX_URLREQUESTPATH,

    FXAAUTH_EVENTSUMMARY,
    FXAAUTH_SOURCEADDRESS,
    FXAAUTH_ACCOUNTID,
    FXAAUTH_SMSRECIPIENT,
    FXAAUTH_EMAILRECIPIENT,
    FXAAUTH_UID
  }

  /** Properties match integers from various payload event types */
  public enum IntegerProperty {
    NORMALIZED_REQUESTSTATUS,

    GLB_STATUS,

    NGINX_STATUS
  }

  private Class<? extends PayloadBase> ptype;
  private Map<StringProperty, String> stringMatchers;
  private Map<StringProperty, Pattern> stringRegexMatchers;
  private Map<IntegerProperty, Integer> integerMatchers;
  private Map<IntegerProperty, EventFilterPayloadRange<Integer>> integerRangeMatchers;

  /**
   * Return true if payload criteria matches
   *
   * @param e Input event
   * @return True on match
   */
  public Boolean matches(Event e) {
    if (ptype != null && !(ptype.isInstance(e.getPayload()))) {
      return false;
    }
    for (Map.Entry<StringProperty, String> entry : stringMatchers.entrySet()) {
      String value = null;
      if (entry.getKey().name().startsWith("NORMALIZED_")) {
        Normalized n = e.getNormalized();
        if (n != null) {
          value = n.eventStringValue(entry.getKey());
        }
      } else {
        value = e.getPayload().eventStringValue(entry.getKey());
      }
      if (value == null) {
        return false;
      }
      if (!(value.equals(entry.getValue()))) {
        return false;
      }
    }
    for (Map.Entry<StringProperty, Pattern> entry : stringRegexMatchers.entrySet()) {
      String value = null;
      if (entry.getKey().name().startsWith("NORMALIZED_")) {
        Normalized n = e.getNormalized();
        if (n != null) {
          value = n.eventStringValue(entry.getKey());
        }
      } else {
        value = e.getPayload().eventStringValue(entry.getKey());
      }
      if (value == null) {
        return false;
      }
      Matcher mat = entry.getValue().matcher(value);
      if (!(mat.matches())) {
        return false;
      }
    }
    for (Map.Entry<IntegerProperty, Integer> entry : integerMatchers.entrySet()) {
      Integer value = null;
      if (entry.getKey().name().startsWith("NORMALIZED_")) {
        Normalized n = e.getNormalized();
        if (n != null) {
          value = n.eventIntegerValue(entry.getKey());
        }
      } else {
        value = e.getPayload().eventIntegerValue(entry.getKey());
      }
      if (value == null) {
        return false;
      }
      if (!(value.equals(entry.getValue()))) {
        return false;
      }
    }
    for (Map.Entry<IntegerProperty, EventFilterPayloadRange<Integer>> entry :
        integerRangeMatchers.entrySet()) {
      Integer value = null;
      if (entry.getKey().name().startsWith("NORMALIZED_")) {
        Normalized n = e.getNormalized();
        if (n != null) {
          value = n.eventIntegerValue(entry.getKey());
        }
      } else {
        value = e.getPayload().eventIntegerValue(entry.getKey());
      }
      if (value == null) {
        return false;
      }
      if (!entry.getValue().inRange(value)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Add a new string regex match to the payload filter
   *
   * @param property {@link EventFilterPayload.StringProperty}
   * @param s String regex pattern to match against
   * @return EventFilterPayload for chaining
   */
  public EventFilterPayload withStringRegexMatch(StringProperty property, String s)
      throws PatternSyntaxException {
    stringRegexMatchers.put(property, Pattern.compile(s));
    return this;
  }

  /**
   * Set configured string regex matchers
   *
   * <p>Patterns are compiled immediately upon invocation of the method.
   *
   * @param stringRegexMatchers Map of key/value pairs
   */
  @JsonProperty("string_regex_match")
  public void setStringRegexMatchers(Map<StringProperty, String> stringRegexMatchers) {
    HashMap<StringProperty, Pattern> buf = new HashMap<>();
    for (Map.Entry<StringProperty, String> entry : stringRegexMatchers.entrySet()) {
      buf.put(entry.getKey(), Pattern.compile(entry.getValue()));
    }
    this.stringRegexMatchers = buf;
  }

  /**
   * Get configured string regex matchers
   *
   * @return Map of key/value pairs
   */
  public Map<StringProperty, String> getStringRegexMatchers() {
    HashMap<StringProperty, String> ret = new HashMap<>();
    for (Map.Entry<StringProperty, Pattern> entry : stringRegexMatchers.entrySet()) {
      ret.put(entry.getKey(), entry.getValue().pattern());
    }
    return ret;
  }

  /**
   * Add a new simple string match to the payload filter
   *
   * @param property {@link EventFilterPayload.StringProperty}
   * @param s String to match against
   * @return EventFilterPayload for chaining
   */
  public EventFilterPayload withStringMatch(StringProperty property, String s) {
    stringMatchers.put(property, s);
    return this;
  }

  /**
   * Set configured string matchers
   *
   * @param stringMatchers Map of key/value pairs
   */
  @JsonProperty("string_match")
  public void setStringMatchers(Map<StringProperty, String> stringMatchers) {
    this.stringMatchers = stringMatchers;
  }

  /**
   * Get configured string matchers
   *
   * @return Map of key/value pairs
   */
  public Map<StringProperty, String> getStringMatchers() {
    return stringMatchers;
  }

  /**
   * Add a new simple integer match to the payload filter
   *
   * @param property {@link EventFilterPayload.IntegerProperty}
   * @param i Integer to match against
   * @return EventFilterPayload for chaining
   */
  public EventFilterPayload withIntegerMatch(IntegerProperty property, Integer i) {
    integerMatchers.put(property, i);
    return this;
  }

  /**
   * Set configured integer matchers
   *
   * @param integerMatchers Map of key/value pairs
   */
  @JsonProperty("integer_match")
  public void setIntegerMatchers(Map<IntegerProperty, Integer> integerMatchers) {
    this.integerMatchers = integerMatchers;
  }

  /**
   * Get configured integer matchers
   *
   * @return Map of key/value pairs
   */
  public Map<IntegerProperty, Integer> getIntegerMatchers() {
    return integerMatchers;
  }

  /**
   * Add an integer range match to the payload filter
   *
   * <p>Will match if the property value falls between low and high inclusively.
   *
   * @param property {@link EventFilterPayload.IntegerProperty}
   * @param low Low value for range match
   * @param high High value for range match
   * @return EventFilterPayload for chaining
   */
  public EventFilterPayload withIntegerRangeMatch(IntegerProperty property, int low, int high) {
    integerRangeMatchers.put(property, new EventFilterPayloadRange<Integer>(low, high));
    return this;
  }

  /**
   * Set configured integer range matchers
   *
   * @param integerRangeMatchers Map of key/value pairs
   */
  @JsonProperty("integer_range_match")
  public void setIntegerRangeMatchers(
      Map<IntegerProperty, EventFilterPayloadRange<Integer>> integerRangeMatchers) {
    this.integerRangeMatchers = integerRangeMatchers;
  }

  /**
   * Get configured integer range matchers
   *
   * @return Map of key/value pairs
   */
  public Map<IntegerProperty, EventFilterPayloadRange<Integer>> getIntegerRangeMatchers() {
    return integerRangeMatchers;
  }

  /**
   * Set payload filter
   *
   * @param className Canonical name of class filter wants
   */
  @JsonProperty("payload_type")
  @SuppressWarnings("unchecked")
  public void setPayloadType(String className) {
    // XXX I'm not sure what a good solution is here to eliminate the need for suppression of the
    // unchecked cast.
    //
    // Right now this seems reasonable enough but this probably needs some more thought.
    Class<?> c;
    try {
      c = Class.forName(className);
    } catch (ClassNotFoundException exc) {
      throw new IllegalArgumentException(exc.getMessage());
    }
    if (PayloadBase.class.isAssignableFrom(c)) {
      ptype = (Class<? extends PayloadBase>) c;
    } else {
      throw new IllegalArgumentException(
          "invalid class for payload type, does not extend PayloadBase");
    }
  }

  /**
   * Get payload filter
   *
   * @return Canonical name of class filter expects, null if unset
   */
  public String getPayloadType() {
    if (ptype == null) {
      return null;
    }
    return ptype.getCanonicalName();
  }

  /**
   * Create new payload filter that additionally verifies against the supplied payload class
   *
   * @param ptype Payload class
   */
  public EventFilterPayload(Class<? extends PayloadBase> ptype) {
    this();
    this.ptype = ptype;
  }

  /** Create new empty payload filter */
  public EventFilterPayload() {
    stringMatchers = new HashMap<StringProperty, String>();
    stringRegexMatchers = new HashMap<StringProperty, Pattern>();
    integerMatchers = new HashMap<IntegerProperty, Integer>();
    integerRangeMatchers = new HashMap<IntegerProperty, EventFilterPayloadRange<Integer>>();
  }
}
