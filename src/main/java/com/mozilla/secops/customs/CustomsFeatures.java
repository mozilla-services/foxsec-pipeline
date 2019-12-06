package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/** CustomsFeatures describes the output of windowed feature extraction */
public class CustomsFeatures implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Considered norminal variance index on point-in-time feature calculation */
  public static final int NOMINAL_VARIANCE_INDEX = 33;

  private ArrayList<Event> events;
  private ArrayList<FxaAuth.EventSummary> collectEvents;

  private HashMap<String, Integer> sourceAddressEventCount;
  private HashMap<String, Integer> uniquePathRequestCount;
  private HashMap<String, Integer> uniquePathSuccessfulRequestCount;

  private int totalEvents;
  private int totalLoginFailureCount;
  private int totalLoginSuccessCount;
  private int totalAccountCreateSuccess;
  private int totalPasswordForgotSendCodeSuccess;
  private int totalPasswordForgotSendCodeFailure;

  private HashMap<FxaAuth.EventSummary, Integer> summarizedEventCounters;
  private int unknownEventCounter;

  private int varianceIndex;

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof CustomsFeatures)) {
      return false;
    }
    CustomsFeatures t = (CustomsFeatures) o;
    return events.equals(t.getEvents());
  }

  @Override
  public int hashCode() {
    return events.hashCode();
  }

  /**
   * Return true if calculated variance index meets or exceeds nominal index value
   *
   * @return boolean
   */
  public boolean nominalVariance() {
    return varianceIndex >= NOMINAL_VARIANCE_INDEX;
  }

  /** Force recalculation of point-in-time statistics */
  public void recalculate() {
    recalculateVariance();
  }

  private void recalculateVariance() {
    // Start at 0
    varianceIndex = 0;

    // If we have more than one unique path, for each unique path increment the
    // index by 1.
    if (uniquePathRequestCount.size() > 1) {
      varianceIndex += uniquePathRequestCount.size();
    }

    // If we have more than one successful path, for each successful path increment
    // the index by 10.
    if (uniquePathRequestCount.size() > 1) {
      varianceIndex += uniquePathSuccessfulRequestCount.size() * 10;
    }

    if (varianceIndex > 100) {
      varianceIndex = 100; // clamp at 100
    }
  }

  /**
   * Merge this feature set with another one
   *
   * @param cf {@link CustomsFeatures} to merge into this object
   */
  public void merge(CustomsFeatures cf) {
    events.addAll(cf.getEvents());

    totalEvents += cf.getTotalEvents();
    totalLoginFailureCount += cf.getTotalLoginFailureCount();
    totalLoginSuccessCount += cf.getTotalLoginSuccessCount();
    totalAccountCreateSuccess += cf.getTotalAccountCreateSuccess();
    totalPasswordForgotSendCodeSuccess += cf.getTotalPasswordForgotSendCodeSuccess();
    totalPasswordForgotSendCodeFailure += cf.getTotalPasswordForgotSendCodeFailure();

    for (Map.Entry<String, Integer> entry : cf.getSourceAddressEventCount().entrySet()) {
      Integer cur =
          sourceAddressEventCount.containsKey(entry.getKey())
              ? sourceAddressEventCount.get(entry.getKey())
              : 0;
      sourceAddressEventCount.put(entry.getKey(), cur + entry.getValue());
    }

    for (Map.Entry<String, Integer> entry : cf.getUniquePathRequestCount().entrySet()) {
      Integer cur =
          uniquePathRequestCount.containsKey(entry.getKey())
              ? uniquePathRequestCount.get(entry.getKey())
              : 0;
      uniquePathRequestCount.put(entry.getKey(), cur + entry.getValue());
    }

    for (Map.Entry<String, Integer> entry : cf.getUniquePathSuccessfulRequestCount().entrySet()) {
      Integer cur =
          uniquePathSuccessfulRequestCount.containsKey(entry.getKey())
              ? uniquePathSuccessfulRequestCount.get(entry.getKey())
              : 0;
      uniquePathSuccessfulRequestCount.put(entry.getKey(), cur + entry.getValue());
    }

    for (Map.Entry<FxaAuth.EventSummary, Integer> entry :
        cf.getSummarizedEventCounters().entrySet()) {
      Integer cur =
          summarizedEventCounters.containsKey(entry.getKey())
              ? summarizedEventCounters.get(entry.getKey())
              : 0;
      summarizedEventCounters.put(entry.getKey(), cur + entry.getValue());
    }
    unknownEventCounter += cf.getUnknownEventCounter();
  }

  /**
   * Get total event count
   *
   * <p>Return the total of all events in the collection, including those that could not be
   * summarized or were not explicitly registered for raw event storage.
   *
   * @return int
   */
  public int getTotalEvents() {
    return totalEvents;
  }

  /**
   * Get variance index
   *
   * @return int
   */
  public int getVarianceIndex() {
    return varianceIndex;
  }

  /**
   * Get unknown event counter
   *
   * @return int
   */
  public int getUnknownEventCounter() {
    return unknownEventCounter;
  }

  /**
   * Get summarized event counters
   *
   * @return HashMap
   */
  public HashMap<FxaAuth.EventSummary, Integer> getSummarizedEventCounters() {
    return summarizedEventCounters;
  }

  /**
   * Get unique path request count
   *
   * @return HashMap
   */
  public HashMap<String, Integer> getUniquePathRequestCount() {
    return uniquePathRequestCount;
  }

  /**
   * Get unique path request count for successful requests
   *
   * @return HashMap
   */
  public HashMap<String, Integer> getUniquePathSuccessfulRequestCount() {
    return uniquePathSuccessfulRequestCount;
  }

  /**
   * Get count of total events per source address
   *
   * @return HashMap
   */
  public HashMap<String, Integer> getSourceAddressEventCount() {
    return sourceAddressEventCount;
  }

  /**
   * Get total password forgot send code failure count for event set
   *
   * @return int
   */
  public int getTotalPasswordForgotSendCodeFailure() {
    return totalPasswordForgotSendCodeFailure;
  }

  /**
   * Get total password forgot send code success count for event set
   *
   * @return int
   */
  public int getTotalPasswordForgotSendCodeSuccess() {
    return totalPasswordForgotSendCodeSuccess;
  }

  /**
   * Get total login failure count for event set
   *
   * @return int
   */
  public int getTotalLoginFailureCount() {
    return totalLoginFailureCount;
  }

  /**
   * Get total login success count for event set
   *
   * @return int
   */
  public int getTotalLoginSuccessCount() {
    return totalLoginSuccessCount;
  }

  /**
   * Get total account create success count for event set
   *
   * @return int
   */
  public int getTotalAccountCreateSuccess() {
    return totalAccountCreateSuccess;
  }

  /**
   * Add a single event to the event list
   *
   * @param e Event
   */
  public void addEvent(Event e) {
    totalEvents++;

    FxaAuth.EventSummary s = CustomsUtil.authGetEventSummary(e);
    if (s != null) {
      switch (s) {
        case LOGIN_FAILURE:
          totalLoginFailureCount++;
          break;
        case LOGIN_SUCCESS:
          totalLoginSuccessCount++;
          break;
        case ACCOUNT_CREATE_SUCCESS:
          totalAccountCreateSuccess++;
          break;
        case PASSWORD_FORGOT_SEND_CODE_SUCCESS:
          totalPasswordForgotSendCodeSuccess++;
          break;
        case PASSWORD_FORGOT_SEND_CODE_FAILURE:
          totalPasswordForgotSendCodeFailure++;
          break;
      }
      // This is something we have a summary for, if it's registered for storage add it
      // to the event collection.
      if (collectEvents.contains(s)) {
        events.add(e);
      }

      Integer cnt = summarizedEventCounters.containsKey(s) ? summarizedEventCounters.get(s) : 0;
      summarizedEventCounters.put(s, cnt + 1);
    } else {
      unknownEventCounter++;
    }

    String sa = CustomsUtil.authGetSourceAddress(e);
    if (sa != null) {
      Integer cnt = sourceAddressEventCount.containsKey(sa) ? sourceAddressEventCount.get(sa) : 0;
      sourceAddressEventCount.put(sa, cnt + 1);
    }

    sa = CustomsUtil.authGetPath(e);
    if (sa != null) {
      Integer cnt = uniquePathRequestCount.containsKey(sa) ? uniquePathRequestCount.get(sa) : 0;
      uniquePathRequestCount.put(sa, cnt + 1);
    }
    Integer status = CustomsUtil.authGetStatus(e);
    if (status != null && status.equals(200)) {
      // Reuse path from previous step here
      Integer cnt =
          uniquePathSuccessfulRequestCount.containsKey(sa)
              ? uniquePathSuccessfulRequestCount.get(sa)
              : 0;
      uniquePathSuccessfulRequestCount.put(sa, cnt + 1);
    }
  }

  /**
   * Get event list
   *
   * @return ArrayList
   */
  public ArrayList<Event> getEvents() {
    return events;
  }

  /**
   * Set event list
   *
   * @param events ArrayList
   */
  public void setEvents(ArrayList<Event> events) {
    this.events = events;
  }

  /**
   * Get all events from event list of a certain type
   *
   * @param t {@link FxaAuth.EventSummary}
   * @return ArrayList
   */
  public ArrayList<Event> getEventsOfType(FxaAuth.EventSummary t) {
    ArrayList<Event> ret = new ArrayList<>();
    for (Event i : events) {
      FxaAuth.EventSummary s = CustomsUtil.authGetEventSummary(i);
      if ((s == null) || (!s.equals(t))) {
        continue;
      }
      ret.add(i);
    }
    return ret;
  }

  CustomsFeatures() {
    events = new ArrayList<Event>();
    collectEvents = Customs.featureSummaryRegistration();

    // Default to 100 if not calculated
    varianceIndex = 100;

    sourceAddressEventCount = new HashMap<String, Integer>();
    uniquePathRequestCount = new HashMap<String, Integer>();
    uniquePathSuccessfulRequestCount = new HashMap<String, Integer>();

    totalEvents = 0;
    totalLoginFailureCount = 0;
    totalLoginSuccessCount = 0;
    totalAccountCreateSuccess = 0;
    totalPasswordForgotSendCodeSuccess = 0;
    totalPasswordForgotSendCodeFailure = 0;

    summarizedEventCounters = new HashMap<FxaAuth.EventSummary, Integer>();
    unknownEventCounter = 0;
  }
}
