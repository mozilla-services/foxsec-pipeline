package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Operate in conjunction with {@link RateLimitAnalyzer} to apply analysis criterion to incoming
 * event stream.
 */
public class RateLimitCriterion extends DoFn<KV<String, Long>, KV<String, Alert>> {
  private static final long serialVersionUID = 1L;

  private final Alert.AlertSeverity severity;
  private final String customsMeta;
  private final Long limit;

  private Logger log;

  /**
   * {@link RateLimitCriterion} static initializer
   *
   * @param severity Severity to use for generated alerts
   * @param customsMeta Customs metadata tag to place on alert
   * @param limit Generate alert if count meets or exceeds limit value in window
   */
  public RateLimitCriterion(Alert.AlertSeverity severity, String customsMeta, Long limit) {
    this.severity = severity;
    this.customsMeta = customsMeta;
    this.limit = limit;
  }

  @Setup
  public void setup() {
    log = LoggerFactory.getLogger(RateLimitCriterion.class);
    log.info(
        "initialized new rate limit criterion analyzer, {} {} {}", severity, customsMeta, limit);
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    KV<String, Long> e = c.element();

    String key = e.getKey();
    Long valueCount = e.getValue();
    if (valueCount < limit) {
      return;
    }

    Alert alert = new Alert();
    alert.setCategory("customs");
    alert.addMetadata("customs_category", customsMeta);
    alert.addMetadata("customs_suspected", key);
    alert.addMetadata("customs_count", valueCount.toString());
    alert.addMetadata("customs_threshold", limit.toString());
    alert.setSeverity(severity);
    c.output(KV.of(key, alert));
  }
}
