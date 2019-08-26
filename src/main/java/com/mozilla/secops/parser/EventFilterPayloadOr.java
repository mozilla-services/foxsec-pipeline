package com.mozilla.secops.parser;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.io.Serializable;
import java.util.ArrayList;

/**
 * A special class of payload filter that supports applying OR logic to matching.
 *
 * <p>If any payload filter added to an OR filter matches, the matches function will return true.
 */
@JsonInclude(Include.NON_NULL)
@JsonDeserialize(as = EventFilterPayloadOr.class)
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
   * Add payload filter
   *
   * @param p Payload filter criteria
   * @return EventFilterPayloadOr for chaining
   */
  public EventFilterPayloadOr addPayloadFilter(EventFilterPayloadInterface p) {
    payloadFilters.add(p);
    return this;
  }

  /**
   * Set configured payload filters
   *
   * @param payloadFilters Array of payload filters
   */
  @JsonProperty("payload_filters")
  public void setPayloadFilters(ArrayList<EventFilterPayloadInterface> payloadFilters) {
    this.payloadFilters = payloadFilters;
  }

  /**
   * Get configured payload filters
   *
   * @return Array of payload filters
   */
  public ArrayList<EventFilterPayloadInterface> getPayloadFilters() {
    return payloadFilters;
  }

  /** Create new empty payload OR filter */
  public EventFilterPayloadOr() {
    payloadFilters = new ArrayList<EventFilterPayloadInterface>();
  }
}
