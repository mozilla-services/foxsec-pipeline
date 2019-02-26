package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import java.io.IOException;
import java.util.Map;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.View;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.GlobalWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.SlidingWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
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

    PCollection<KV<String, Event>> winevents =
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
                    .accumulatingFiredPanes());

    PCollectionView<Map<String, Iterable<Event>>> eventView =
        winevents.apply(View.<String, Event>asMultimap());

    return winevents
        .apply(Count.<String, Event>perKey())
        .apply(
            ParDo.of(new RateLimitCriterion(detectorName, cfg, eventView, monitoredResource))
                .withSideInputs(eventView))
        .apply(
            "suppression windows",
            Window.<KV<String, Alert>>into(new GlobalWindows())
                .triggering(
                    Repeatedly.forever(
                        AfterProcessingTime.pastFirstElementInPane()
                            .plusDelayOf(Duration.standardSeconds(5L)))))
        .apply(ParDo.of(new RateLimitSuppressor(cfg)));
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
