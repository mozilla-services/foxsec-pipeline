package com.mozilla.secops.parser;

import java.io.Serializable;

/** Numeric range comparison for use in {@link EventFilter} */
public class EventFilterPayloadRange<T extends Comparable<T>> implements Serializable {
  private static final long serialVersionUID = 1L;

  private T low;
  private T high;

  /**
   * Return true if value is in range
   *
   * @param value Value to compare against range
   * @return True if in range, false otherwise
   */
  public boolean inRange(T value) {
    if ((value.compareTo(low) >= 0) && (value.compareTo(high) <= 0)) {
      return true;
    }
    return false;
  }

  /**
   * Initialize new {@link EventFilterPayloadRange}
   *
   * @param low Low value for range (inclusive)
   * @param high High value for range (inclusive)
   */
  public EventFilterPayloadRange(T low, T high) {
    this.low = low;
    this.high = high;
  }
}
