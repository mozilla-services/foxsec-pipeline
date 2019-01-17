package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.ArrayList;

/** Rule within an event filter */
public class EventFilterRule implements Serializable {
  private static final long serialVersionUID = 1L;

  private Payload.PayloadType wantSubtype;
  private Normalized.Type wantNormalizedType;
  private String wantStackdriverProject;
  private ArrayList<EventFilterPayload> payloadFilters;

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
    for (EventFilterPayload p : payloadFilters) {
      if (!p.matches(e)) {
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
    if (wantSubtype != null) {
      if (e.getPayloadType() != wantSubtype) {
        return null;
      }
    }
    for (EventFilterPayload p : payloadFilters) {
      ArrayList<String> values = p.getKeys(e);
      if (values == null) {
        return null;
      }
      ret.addAll(values);
    }
    return ret;
  }

  /**
   * Add payload filter
   *
   * @param p Payload filter criteria
   * @return EventFilterRule for chaining
   */
  public EventFilterRule addPayloadFilter(EventFilterPayload p) {
    payloadFilters.add(p);
    return this;
  }

  /**
   * Add match criteria for a payload subtype
   *
   * @param p Payload type
   * @return EventFilterRule for chaining
   */
  public EventFilterRule wantSubtype(Payload.PayloadType p) {
    wantSubtype = p;
    return this;
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
  public EventFilterRule wantStackdriverProject(String project) {
    wantStackdriverProject = project;
    return this;
  }

  /**
   * Add match criteria for a normalized event type
   *
   * @param n Normalized event type
   * @return EventFilterRule for chaining
   */
  public EventFilterRule wantNormalizedType(Normalized.Type n) {
    wantNormalizedType = n;
    return this;
  }

  /** Create new empty {@link EventFilterRule} */
  public EventFilterRule() {
    payloadFilters = new ArrayList<EventFilterPayload>();
  }
}
