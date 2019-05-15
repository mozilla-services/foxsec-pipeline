package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.Parser;
import java.util.Map;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollectionView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Operate in conjunction with {@link RateLimitAnalyzer} to apply analysis criterion to incoming
 * event stream.
 */
public class RateLimitCriterion extends DoFn<KV<String, Long>, KV<String, Alert>> {
  private static final long serialVersionUID = 1L;

  private final String detectorName;
  private final String monitoredResource;
  private final CustomsCfgEntry cfg;
  private final PCollectionView<Map<String, Iterable<Event>>> eventView;
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
  public RateLimitCriterion(
      String detectorName,
      CustomsCfgEntry cfg,
      PCollectionView<Map<String, Iterable<Event>>> eventView,
      String monitoredResource) {
    this.detectorName = detectorName;
    this.cfg = cfg;
    this.eventView = eventView;
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
    Long count = c.element().getValue();
    if (count < cfg.getThreshold()) {
      return;
    }

    String key = c.element().getKey();
    Map<String, Iterable<Event>> eventMap = c.sideInput(eventView);

    Alert alert = new Alert();
    alert.setSeverity(severity);

    Iterable<Event> eventList = eventMap.get(key);
    if (eventList == null) {
      log.info("dropping alert for {}, event list was empty", key);
      return;
    }

    // Set the alert timestamp based on the latest event timestamp
    alert.setTimestamp(Parser.getLatestTimestamp(eventList));

    alert.setCategory("customs");
    alert.addMetadata("customs_category", detectorName);
    alert.addMetadata("threshold", cfg.getThreshold().toString());
    alert.addMetadata("count", count.toString());
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
