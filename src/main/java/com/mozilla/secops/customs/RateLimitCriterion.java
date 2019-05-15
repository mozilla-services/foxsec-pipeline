package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.Parser;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Operate in conjunction with {@link RateLimitAnalyzer} to apply analysis criterion to incoming
 * event stream.
 */
public class RateLimitCriterion extends DoFn<KV<String, RateLimitCandidate>, KV<String, Alert>> {
  private static final long serialVersionUID = 1L;

  private final String detectorName;
  private final String monitoredResource;
  private final CustomsCfgEntry cfg;
  private final Alert.AlertSeverity severity;

  private Logger log;

  /**
   * Constructor for {@link RateLimitCriterion}
   *
   * @param detectorName Detector name
   * @param cfg Customs configuration entry
   * @param eventView Event view to use for side input
   * @param monitoredResource Monitored resource name
   */
  public RateLimitCriterion(String detectorName, CustomsCfgEntry cfg, String monitoredResource) {
    this.detectorName = detectorName;
    this.cfg = cfg;
    this.monitoredResource = monitoredResource;

    severity = Alert.AlertSeverity.INFORMATIONAL;
  }

  @Setup
  public void setup() {
    log = LoggerFactory.getLogger(RateLimitCriterion.class);
    log.info("initialized new rate limit criterion analyzer, {} {}", severity, detectorName);
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    RateLimitCandidate rlc = c.element().getValue();

    int count = rlc.getEventCount();
    if (count < cfg.getThreshold()) {
      return;
    }

    String key = c.element().getKey();
    Iterable<Event> eventList = rlc.getEvents();

    Alert alert = new Alert();
    alert.setSeverity(severity);

    // Set the alert timestamp based on the latest event timestamp
    alert.setTimestamp(Parser.getLatestTimestamp(eventList));

    alert.setCategory("customs");
    alert.addMetadata("customs_category", detectorName);
    alert.addMetadata("threshold", cfg.getThreshold().toString());
    alert.addMetadata("count", new Integer(count).toString());
    alert.setNotifyMergeKey(detectorName);

    String[] kelements = EventFilter.splitKey(key);
    int kelementCount = kelements.length;
    if (kelementCount != cfg.getMetadataAssembly().length) {
      log.warn("dropping alert for {}, metadata assembly length did not match key count", key);
      return;
    }
    for (int i = 0; i < kelementCount; i++) {
      alert.addMetadata(cfg.getMetadataAssembly()[i].replaceFirst("mask:", ""), kelements[i]);
    }
    alert.setSummary(
        monitoredResource + " " + String.format(cfg.getSummaryAssemblyFmt(), (Object[]) kelements));

    String[] melements = new String[kelements.length];
    Boolean mField = false;
    for (int i = 0; i < kelements.length; i++) {
      if (cfg.getMetadataAssembly()[i].startsWith("mask:")) {
        melements[i] = "<<masked>>";
        mField = true;
      } else {
        melements[i] = kelements[i];
      }
    }
    if (mField) {
      alert.setMaskedSummary(
          monitoredResource
              + " "
              + String.format(cfg.getSummaryAssemblyFmt(), (Object[]) melements));
    }

    if (!alert.hasCorrectFields()) {
      throw new IllegalArgumentException("alert has invalid field configuration");
    }

    c.output(KV.of(key, alert));
  }
}
