package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** Numeric range comparison for use in {@link EventFilter} */
public class EventFilterPayloadRange<T extends Comparable<T>> implements Serializable {
  private static final long serialVersionUID = 1L;

  private T low;
  private T high;

  /**
   * Set low value
   *
   * @param low Low range value
   */
  @JsonProperty("low")
  void setLow(T low) {
    this.low = low;
  }

  /**
   * Get low value
   *
   * @return Low range value
   */
  public T getLow() {
    return low;
  }

  /**
   * Set high value
   *
   * @param high High range vlaue
   */
  @JsonProperty("high")
  void setHigh(T high) {
    this.high = high;
  }

  /**
   * Get high value
   *
   * @return High range value
   */
  public T getHigh() {
    return high;
  }

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
  @JsonCreator
  public EventFilterPayloadRange(@JsonProperty("low") T low, @JsonProperty("high") T high) {
    this.low = low;
    this.high = high;
  }
}
