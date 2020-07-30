package com.mozilla.secops.alert;

import java.io.Serializable;
import org.apache.beam.sdk.state.StateSpec;
import org.apache.beam.sdk.state.StateSpecs;
import org.apache.beam.sdk.state.TimeDomain;
import org.apache.beam.sdk.state.Timer;
import org.apache.beam.sdk.state.TimerSpec;
import org.apache.beam.sdk.state.TimerSpecs;
import org.apache.beam.sdk.state.ValueState;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements generic alert suppression
 *
 * <p>{@link AlertSuppressor} can be used to suppress additional alerts for a given key. The first
 * time an alert is seen for a given key, it will be emitted and state will be stored indicating
 * when it was sent. Any further alerts for that key will be suppressed until the state value
 * expires.
 *
 * <p>This implementation uses state, so care should be taken to ensure the collection being
 * suppressed is windowed into windows that are appropriate for the state expiration value.
 */
public class AlertSuppressor extends DoFn<KV<String, Alert>, Alert> {
  private static final long serialVersionUID = 1L;

  private final Long expiry;
  protected Logger log;

  /** Internal class for alert suppression state */
  public static class AlertSuppressionState implements Serializable {
    private static final long serialVersionUID = 1L;

    /** State key */
    public String key;

    /**
     * Counter value for extended suppression
     *
     * <p>Relies on the presence of a count metadata value.
     */
    public Integer count;

    /** Timestamp */
    public Instant timestamp;
  }

  @StateId("counter")
  private final StateSpec<ValueState<AlertSuppressionState>> counterState = StateSpecs.value();

  @TimerId("expiryState")
  private final TimerSpec counterExpiry = TimerSpecs.timer(TimeDomain.PROCESSING_TIME);

  /**
   * Initialize new AlertSuppressor
   *
   * @param expiry State expiry timer in seconds
   */
  public AlertSuppressor(Long expiry) {
    log = LoggerFactory.getLogger(AlertSuppressor.class);
    this.expiry = expiry * 1000; // Convert to milliseconds for comparison
  }

  private Boolean isExpired(AlertSuppressionState ss, AlertSuppressionState newss) {
    if ((newss.timestamp.getMillis() - ss.timestamp.getMillis()) > expiry) {
      // The old state data is too old for consideration
      return true;
    }
    return false;
  }

  protected Boolean shouldSuppress(AlertSuppressionState ss, AlertSuppressionState newss) {
    return true;
  }

  private void updateTimer(Timer timer) {
    // Update the expiry timer for the state entry. This is only used to clear old state we
    // don't want anymore, so to be safe set it to one minute beyond the actual expiry time
    // for the entry.
    timer.offset(Duration.millis(expiry + 60000L)).setRelative();
  }

  @OnTimer("expiryState")
  public void onExpiry(
      OnTimerContext c, @StateId("counter") ValueState<AlertSuppressionState> counter) {
    counter.clear();
  }

  @ProcessElement
  public void processElement(
      ProcessContext c,
      @StateId("counter") ValueState<AlertSuppressionState> counter,
      @TimerId("expiryState") Timer counterExpiry) {
    String key = c.element().getKey();
    Alert a = c.element().getValue();

    // Prepare a new state value to use if we need to set it later
    AlertSuppressionState newss = new AlertSuppressionState();
    newss.key = key;
    newss.timestamp = a.getTimestamp().toInstant();
    if (a.getMetadataValue(AlertMeta.Key.COUNT) != null) {
      newss.count = new Integer(a.getMetadataValue(AlertMeta.Key.COUNT));
    }

    AlertSuppressionState ss = counter.read();

    if (ss == null) {
      // This is a new alert, set values in state and emit
      counter.write(newss);
      updateTimer(counterExpiry);
      c.output(a);
      return;
    }

    updateTimer(counterExpiry);

    if (isExpired(ss, newss)) {
      // If the state data is too old for consideration, update state with new information
      // and emit the alert
      counter.write(newss);
      c.output(a);
      return;
    }

    // Finally, apply additional suppression logic, in this class we always return true here but
    // this is intended to be overridden as required
    if (shouldSuppress(ss, newss)) {
      // If the new alert timestamp precisely matched the timestamp we had stored in state, don't
      // log it as it's likely the same alert being emitted in a different window or in the on-time
      // pane, but drop it either way
      if (!newss.timestamp.equals(ss.timestamp)) {
        log.info("suppressing additional alert for {}", key);
      }
      return;
    }
    counter.write(newss);
    c.output(a);
  }
}
