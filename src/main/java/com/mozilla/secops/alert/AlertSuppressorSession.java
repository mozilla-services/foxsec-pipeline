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
 * Alert suppression using session gap based expiry
 *
 * <p>Based on AlertSuppressor: creates a suppressor where we extend the expiry each time we stashed
 * changes suppress an alert for a key - essentially creating a session. The same expiry logic is
 * applied, however in this case if a new alert comes in for a key we have state for and the
 * metadata count value is different then what was seen prior, the alert will be emitted and state
 * will be updated.
 */
public class AlertSuppressorSession extends DoFn<KV<String, Alert>, Alert> {
  private static final long serialVersionUID = 1L;

  private final Long expiry;
  protected Logger log;

  /** Internal class for alert suppression state */
  public static class AlertSuppressionState implements Serializable {
    private static final long serialVersionUID = 1L;

    /** State key */
    private String key;

    /** Timestamp */
    private Instant timestamp;
  }

  @StateId("counter")
  private final StateSpec<ValueState<AlertSuppressionState>> counterState = StateSpecs.value();

  @TimerId("expiryState")
  private final TimerSpec counterExpiry = TimerSpecs.timer(TimeDomain.PROCESSING_TIME);

  public AlertSuppressorSession(Long sessionGapDuration) {
    log = LoggerFactory.getLogger(AlertSuppressorSession.class);
    this.expiry = sessionGapDuration * 1000;
  }

  protected Boolean isExpired(AlertSuppressionState ss, AlertSuppressionState newss) {
    return (newss.timestamp.getMillis() - ss.timestamp.getMillis()) > expiry;
  }

  protected void updateTimer(Timer timer) {
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

    // log a message if timestamp is different as this is likely
    // a different alert - if timestamp is the same it's likely from same
    // event but different window firing
    if (!newss.timestamp.equals(ss.timestamp)) {
      log.info("suppressing additional alert for {}", key);
    }

    // always update the counter if an alert is suppressed
    // but do not output the alert
    counter.write(newss);
  }
}
