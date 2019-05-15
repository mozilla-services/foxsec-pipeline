package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.UUID;

/** Describes candidate information used in {@link RateLimitCriterion} */
public class RateLimitCandidate implements Serializable {
  private static final long serialVersionUID = 1L;

  private UUID candId;
  private int eventCount;
  private ArrayList<Event> events;

  /** Initialize new RateLimitCandidate */
  public RateLimitCandidate() {
    candId = UUID.randomUUID();
    eventCount = 0;
    events = new ArrayList<Event>();
  }

  /**
   * Get number of events in candidate
   *
   * @return Event count
   */
  public int getEventCount() {
    return eventCount;
  }

  /**
   * Get events
   *
   * @return Iterable of events
   */
  public Iterable<Event> getEvents() {
    return events;
  }

  /**
   * Add event to candidate
   *
   * @param e Event
   */
  public void addEvent(Event e) {
    events.add(e);
    eventCount++;
  }

  /**
   * Return unique candidate ID
   *
   * @return UUID
   */
  public UUID getCandidateId() {
    return candId;
  }

  @Override
  public boolean equals(Object o) {
    RateLimitCandidate t = (RateLimitCandidate) o;
    return getCandidateId().equals(t.getCandidateId());
  }

  @Override
  public int hashCode() {
    return candId.hashCode();
  }
}
