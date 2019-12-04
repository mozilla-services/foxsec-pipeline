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

  private ArrayList<Event> events;

  private HashMap<String, Integer> sourceAddressEventCount;

  private int totalLoginFailureCount;
  private int totalLoginSuccessCount;
  private int totalAccountCreateSuccess;
  private int totalPasswordForgotSendCodeSuccess;
  private int totalPasswordForgotSendCodeFailure;

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
   * Merge this feature set with another one
   *
   * @param cf {@link CustomsFeatures} to merge into this object
   */
  public void merge(CustomsFeatures cf) {
    events.addAll(cf.getEvents());

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
    events.add(e);

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
    }

    String sa = CustomsUtil.authGetSourceAddress(e);
    if (sa != null) {
      Integer cnt = sourceAddressEventCount.containsKey(sa) ? sourceAddressEventCount.get(sa) : 0;
      sourceAddressEventCount.put(sa, cnt + 1);
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

    sourceAddressEventCount = new HashMap<String, Integer>();

    totalLoginFailureCount = 0;
    totalLoginSuccessCount = 0;
    totalAccountCreateSuccess = 0;
    totalPasswordForgotSendCodeSuccess = 0;
    totalPasswordForgotSendCodeFailure = 0;
  }
}
