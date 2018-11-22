package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import java.util.Collection;
import org.apache.beam.sdk.state.StateSpec;
import org.apache.beam.sdk.state.StateSpecs;
import org.apache.beam.sdk.state.ValueState;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.values.KV;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link DoFn} to apply suppression of alerts.
 *
 * <p>The input is expected to be a {@link KV} where the key is a string identifier that suppression
 * is desired for, and the value is any alerts associated with this identifier. State is used within
 * the applicable window for the event.
 *
 * <p>If no alert has been seen for a given identifier, the earliest alert for the identifier is
 * submitted based on the alert timestamp. If the identifier has already been seen in-window, a
 * notice is output in the logs and the alerts are dropped.
 */
public class RateLimitSuppressor extends DoFn<KV<String, Iterable<Alert>>, Alert> {
  private static final long serialVersionUID = 1L;

  private Logger log;

  @StateId("suppression")
  private final StateSpec<ValueState<Boolean>> suppression = StateSpecs.value();

  /** Create new {@link RateLimitSuppressor} */
  public RateLimitSuppressor() {
    log = LoggerFactory.getLogger(RateLimitSuppressor.class);
  }

  @ProcessElement
  public void processElement(
      ProcessContext c, BoundedWindow w, @StateId("suppression") ValueState<Boolean> suppress) {
    KV<String, Iterable<Alert>> el = c.element();
    String key = el.getKey();
    Iterable<Alert> alertval = el.getValue();

    if (!(alertval instanceof Collection)) {
      log.warn("value was not an instance of collection");
      return;
    }
    Alert[] alerts = ((Collection<Alert>) alertval).toArray(new Alert[0]);
    if (alerts.length == 0) {
      return;
    }

    Boolean sflag = suppress.read();
    if (sflag != null && sflag) {
      log.info("suppressing additional in-window alert for {}", key);
      return;
    }
    suppress.write(true);
    log.info(
        "emitting alert for {} in window {} [{}]",
        key,
        w.maxTimestamp(),
        w.maxTimestamp().getMillis());

    // Write the earliest timestamp for the alert set we can find
    DateTime min = null;
    int idx = -1;
    for (int i = 0; i < alerts.length; i++) {
      if (min == null) {
        min = alerts[i].getTimestamp();
        idx = i;
        continue;
      }
      if (alerts[i].getTimestamp().isBefore(min)) {
        min = alerts[i].getTimestamp();
        idx = i;
      }
    }
    log.info(
        "emit {} {} {}",
        alerts[idx].getAlertId(),
        alerts[idx].getCategory(),
        alerts[idx].getTimestamp());
    c.output(alerts[idx]);
  }
}
