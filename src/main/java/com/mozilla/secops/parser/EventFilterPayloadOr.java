package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.ArrayList;

/**
 * A special class of payload filter that supports applying OR logic to matching.
 *
 * <p>If any payload filter added to an OR filter matches, the matches function will return true.
 */
public class EventFilterPayloadOr implements EventFilterPayloadInterface, Serializable {
  private static final long serialVersionUID = 1L;

  private ArrayList<EventFilterPayloadInterface> payloadFilters;

  /**
   * Return true if payload criteria matches
   *
   * @param e Input event
   * @return True on match
   */
  public Boolean matches(Event e) {
    for (EventFilterPayloadInterface p : payloadFilters) {
      if (p.matches(e)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Return extracted keys from event based on string selectors
   *
   * @param e Input event
   * @return {@link ArrayList} of extracted keys
   */
  public ArrayList<String> getKeys(Event e) {
    throw new IllegalArgumentException("or filter cannot be used in keying selector");
  }

  /**
   * Add payload filter
   *
   * @param p Payload filter criteria
   * @return EventFilterPayloadOr for chaining
   */
  public EventFilterPayloadOr addPayloadFilter(EventFilterPayloadInterface p) {
    payloadFilters.add(p);
    return this;
  }

  /** Create new empty payload OR filter */
  public EventFilterPayloadOr() {
    payloadFilters = new ArrayList<EventFilterPayloadInterface>();
  }
}
