package com.mozilla.secops.parser;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/** Rule within an event filter */
@JsonInclude(Include.NON_NULL)
public class EventFilterRule implements Serializable {
  private static final long serialVersionUID = 1L;

  private Payload.PayloadType wantSubtype;
  private Normalized.Type wantNormalizedType;
  private String wantStackdriverProject;
  private Map<String, String> wantStackdriverLabel;
  private ArrayList<EventFilterPayloadInterface> payloadFilters;

  private ArrayList<EventFilterRule> exceptRules;

  /**
   * Test if event matches rule
   *
   * @param e Event to match against rule
   * @return True if event matches
   */
  public Boolean matches(Event e) {
    if (wantStackdriverProject != null) {
      String p = e.getStackdriverProject();
      if ((p == null) || !(p.equals(wantStackdriverProject))) {
        return false;
      }
    }
    if (!(wantStackdriverLabel.isEmpty())) {
      for (Map.Entry<String, String> entry : wantStackdriverLabel.entrySet()) {
        String wantKey = entry.getKey();
        String wantValue = entry.getValue();

        String hasValue = e.getStackdriverLabel(wantKey);
        if (hasValue == null) {
          // Label isn't found
          return false;
        }
        if (!(hasValue.equals(wantValue))) {
          return false;
        }
      }
    }
    if (wantSubtype != null) {
      if (e.getPayloadType() != wantSubtype) {
        return false;
      }
    }
    if (wantNormalizedType != null) {
      if (!(e.getNormalized().isOfType(wantNormalizedType))) {
        return false;
      }
    }
    for (EventFilterPayloadInterface p : payloadFilters) {
      if (!p.matches(e)) {
        return false;
      }
    }

    // If we got here the event matches the rule so far, so apply the negation
    // list
    for (EventFilterRule r : exceptRules) {
      if (r.matches(e)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Install negation rules for this filter rule
   *
   * <p>Even if the filter rule matches, if the event also matches anything in the negation list it
   * will not match the rule.
   *
   * @param r {@link EventFilterRule} to add to negation list
   * @return EventFilterRule for chaining
   */
  public EventFilterRule except(EventFilterRule r) {
    exceptRules.add(r);
    return this;
  }

  /**
   * Set except rules
   *
   * @param erules List of {@link EventFilterRule} for exceptions
   */
  @JsonProperty("except")
  public void setExceptRules(ArrayList<EventFilterRule> erules) {
    exceptRules = erules;
  }

  /**
   * Get except rules
   *
   * @return Array of exception {@link EventFilterRule}
   */
  public ArrayList<EventFilterRule> getExceptRules() {
    return exceptRules;
  }

  /**
   * Add payload filter
   *
   * @param p Payload filter criteria
   * @return EventFilterRule for chaining
   */
  public EventFilterRule addPayloadFilter(EventFilterPayloadInterface p) {
    payloadFilters.add(p);
    return this;
  }

  /**
   * Set payload filters
   *
   * @param filters Array of {@link EventFilterPayloadInterface}
   */
  @JsonProperty("payload_filters")
  public void setPayloadFilters(ArrayList<EventFilterPayloadInterface> filters) {
    payloadFilters = filters;
  }

  /**
   * Get payload filters
   *
   * @return Array of payload filters
   */
  public ArrayList<EventFilterPayloadInterface> getPayloadFilters() {
    return payloadFilters;
  }

  /**
   * Add match criteria for a payload subtype
   *
   * @param p Payload type
   * @return EventFilterRule for chaining
   */
  @JsonSetter("subtype")
  public EventFilterRule wantSubtype(Payload.PayloadType p) {
    wantSubtype = p;
    return this;
  }

  /**
   * Get want subtype value
   *
   * @return Payload type, or null if unset
   */
  @JsonProperty("subtype")
  public Payload.PayloadType getWantSubtype() {
    return wantSubtype;
  }

  /**
   * Add match criteria for Stackdriver project
   *
   * <p>If this rule is installed, an event will only match if it is an event from Stackdriver and
   * the project matches the supplied argument.
   *
   * @param project Project name to match against
   * @return EventFilterRule for chaining
   */
  @JsonSetter("stackdriver_project")
  public EventFilterRule wantStackdriverProject(String project) {
    wantStackdriverProject = project;
    return this;
  }

  /**
   * Get want Stackdriver project value
   *
   * @return Stackdrive project string, or null if unset
   */
  @JsonProperty("stackdriver_project")
  public String getWantStackdriverProject() {
    return wantStackdriverProject;
  }

  /**
   * Add match criteria for a Stackdriver label
   *
   * <p>If this rule is installed, an event will only match if it is an event from Stackdriver and
   * has a label with the specified key and value.
   *
   * @param key Label key
   * @param value Label value
   * @return EventFilterRule for chaining
   */
  public EventFilterRule wantStackdriverLabel(String key, String value) {
    wantStackdriverLabel.put(key, value);
    return this;
  }

  /**
   * Set Stackdriver label filters
   *
   * @param labels Map of key/value pairs
   */
  @JsonProperty("stackdriver_labels")
  public void setWantStackdriverLabels(Map<String, String> labels) {
    wantStackdriverLabel = labels;
  }

  /**
   * Get Stackdriver label filters
   *
   * @return Map of key/value pairs
   */
  public Map<String, String> getWantStackdriverLabels() {
    return wantStackdriverLabel;
  }

  /**
   * Add match criteria for a normalized event type
   *
   * @param n Normalized event type
   * @return EventFilterRule for chaining
   */
  @JsonSetter("normalized_type")
  public EventFilterRule wantNormalizedType(Normalized.Type n) {
    wantNormalizedType = n;
    return this;
  }

  /**
   * Get want normalized type value
   *
   * @return Normalized type, or null if unset
   */
  @JsonProperty("normalized_type")
  public Normalized.Type getWantNormalizedType() {
    return wantNormalizedType;
  }

  /** Create new empty {@link EventFilterRule} */
  public EventFilterRule() {
    payloadFilters = new ArrayList<EventFilterPayloadInterface>();
    exceptRules = new ArrayList<EventFilterRule>();
    wantStackdriverLabel = new HashMap<String, String>();
  }
}
