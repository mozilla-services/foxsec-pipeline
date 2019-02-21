package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import org.apache.beam.sdk.state.StateSpec;
import org.apache.beam.sdk.state.StateSpecs;
import org.apache.beam.sdk.state.ValueState;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link DoFn} to apply suppression of alerts.
 *
 * <p>The input is expected to be a {@link KV} where the key is a string identifier that suppression
 * is desired for, and the value is an alert associated with this identifier. Global window state is
 * used to suppress additional alerts for the identifier until the suppression timeframe configured
 * for a particular detector has expired.
 */
public class RateLimitSuppressor extends DoFn<KV<String, Alert>, Alert> {
  private static final long serialVersionUID = 1L;

  private Logger log;
  private final CustomsCfgEntry cfg;

  @StateId("id_last_alert")
  private final StateSpec<ValueState<Instant>> lastAlert = StateSpecs.value();

  /**
   * Create new {@link RateLimitSuppressor}
   *
   * @param cfg Customs configuration entry
   */
  public RateLimitSuppressor(CustomsCfgEntry cfg) {
    log = LoggerFactory.getLogger(RateLimitSuppressor.class);
    this.cfg = cfg;
  }

  @ProcessElement
  public void processElement(ProcessContext c, @StateId("id_last_alert") ValueState<Instant> last) {
    String key = c.element().getKey();
    Alert alertval = c.element().getValue();

    Long suppressMillis = cfg.getAlertSuppressionLength() * 1000;

    Instant l = last.read();
    if (l != null) {
      Long delta = new Instant().getMillis() - l.getMillis();
      if (delta < suppressMillis) {
        log.info("suppressing additional alert for {}, {} < {}", key, delta, suppressMillis);
        return;
      }
    }
    last.write(new Instant());

    log.info("emitting alert for {}", key);
    log.info("emit: {}", alertval.toJSON());
    c.output(alertval);
  }
}
