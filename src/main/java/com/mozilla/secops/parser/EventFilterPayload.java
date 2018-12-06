package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Can be associated with {@link EventFilterRule} for payload matching */
public class EventFilterPayload implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Properties match strings from various payload event types */
  public enum StringProperty {
    NORMALIZED_SUBJECTUSER,

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
    CLOUDTRAIL_MFA
  }

  private Class<? extends PayloadBase> ptype;
  private Map<StringProperty, String> stringMatchers;
  private Map<StringProperty, Pattern> stringRegexMatchers;

  private ArrayList<StringProperty> stringSelectors;

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
      String value = e.getPayload().eventStringValue(entry.getKey());
      if (value == null) {
        return false;
      }
      if (!(value.equals(entry.getValue()))) {
        return false;
      }
    }
    for (Map.Entry<StringProperty, Pattern> entry : stringRegexMatchers.entrySet()) {
      String value = e.getPayload().eventStringValue(entry.getKey());
      if (value == null) {
        return false;
      }
      Matcher mat = entry.getValue().matcher(value);
      if (!(mat.matches())) {
        return false;
      }
    }
    return true;
  }

  /**
   * Return extracted keys from event based on string selectors
   *
   * @param e Input event
   * @return {@link ArrayList} of extracted keys
   */
  public ArrayList<String> getKeys(Event e) {
    ArrayList<String> ret = new ArrayList<String>();
    for (StringProperty s : stringSelectors) {
      String value;
      if (s.name().startsWith("NORMALIZED_")) {
        Normalized n = e.getNormalized();
        if (n == null) {
          return null;
        }
        value = n.eventStringValue(s);
      } else {
        value = e.getPayload().eventStringValue(s);
      }
      if (value == null) {
        return null;
      }
      ret.add(value);
    }
    return ret;
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
   * Add a string selector for filter keying operations
   *
   * @param property Property to extract for key
   * @return EventFilterPayload for chaining
   */
  public EventFilterPayload withStringSelector(StringProperty property) {
    stringSelectors.add(property);
    return this;
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
    stringSelectors = new ArrayList<StringProperty>();
  }
}
