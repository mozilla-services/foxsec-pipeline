package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertSuppressor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.SlidingWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;

/** Generic rate limiting heuristic */
public class RateLimitAnalyzer extends PTransform<PCollection<Event>, PCollection<Alert>> {
  private static final long serialVersionUID = 1L;

  private CustomsCfgEntry cfg;
  private String detectorName;
  private String monitoredResource;

  @Override
  public PCollection<Alert> expand(PCollection<Event> input) {
    EventFilter filter = null;
    try {
      filter = cfg.getEventFilterCfg().getEventFilter("default");
    } catch (IOException exc) {
      return null;
    }

    PCollection<KV<String, RateLimitCandidate>> winevents =
        input
            .apply(EventFilter.getKeyingTransform(filter))
            .apply(
                "analysis windows",
                Window.<KV<String, Event>>into(
                        SlidingWindows.of(Duration.standardSeconds(cfg.getSlidingWindowLength()))
                            .every(Duration.standardSeconds(cfg.getSlidingWindowSlides())))
                    .triggering(
                        Repeatedly.forever(
                            AfterWatermark.pastEndOfWindow()
                                .withEarlyFirings(
                                    AfterProcessingTime.pastFirstElementInPane()
                                        .plusDelayOf(Duration.standardSeconds(5L)))))
                    .withAllowedLateness(Duration.ZERO)
                    .accumulatingFiredPanes())
            .apply("gbk", GroupByKey.<String, Event>create())
            .apply(
                "candidate conversion",
                ParDo.of(
                    new DoFn<KV<String, Iterable<Event>>, KV<String, RateLimitCandidate>>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        RateLimitCandidate r = new RateLimitCandidate();
                        for (Event e : c.element().getValue()) {
                          r.addEvent(e);
                        }
                        // Don't emit entries with single events since we will never alert on them
                        if (r.getEventCount() <= 1) {
                          return;
                        }
                        c.output(KV.of(c.element().getKey(), r));
                      }
                    }));

    return winevents
        .apply(ParDo.of(new RateLimitCriterion(detectorName, cfg, monitoredResource)))
        .apply("suppression windows", new GlobalTriggers<KV<String, Alert>>(5))
        .apply(ParDo.of(new AlertSuppressor(cfg.getAlertSuppressionLength())));
  }

  /**
   * Create new RateLimitAnalyzer
   *
   * @param detectorName Detector name
   * @param cfg Customs configuration entry
   * @param monitoredResource Monitored resource name
   */
  public RateLimitAnalyzer(String detectorName, CustomsCfgEntry cfg, String monitoredResource) {
    this.detectorName = detectorName;
    this.cfg = cfg;
    this.monitoredResource = monitoredResource;
  }
}
