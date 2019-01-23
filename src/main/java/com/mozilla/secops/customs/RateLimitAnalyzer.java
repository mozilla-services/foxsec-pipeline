package com.mozilla.secops.customs;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import java.io.Serializable;
import java.util.Map;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.View;
import org.apache.beam.sdk.transforms.windowing.AfterPane;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.SlidingWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.Duration;

/** Generic rate limiting heuristic */
public class RateLimitAnalyzer implements Serializable {
  private static final long serialVersionUID = 1L;

  private String identifier;
  private String monitoredResource;

  private EventFilter filter;

  private Duration windowLength;
  private Duration windowSlideLength;

  private Long limitCount;
  private Alert.AlertSeverity severity;

  private Duration suppressLength;

  public static PTransform<PCollection<Event>, PCollection<Alert>> getTransform(
      RateLimitAnalyzer analyzer) {
    return new PTransform<PCollection<Event>, PCollection<Alert>>() {
      private static final long serialVersionUID = 1L;

      @Override
      public PCollection<Alert> expand(PCollection<Event> input) {
        PCollection<KV<String, Event>> winevents =
            input
                .apply(EventFilter.getKeyingTransform(analyzer.getFilter()))
                .apply(
                    "analysis windows",
                    Window.<KV<String, Event>>into(
                            SlidingWindows.of(analyzer.getWindowLength())
                                .every(analyzer.getWindowSlideLength()))
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
                ParDo.of(
                        new RateLimitCriterion(
                            analyzer.getAlertCriteriaSeverity(),
                            analyzer.getIdentifier(),
                            analyzer.getAlertCriteriaLimit(),
                            eventView,
                            analyzer.getMonitoredResource()))
                    .withSideInputs(eventView))
            .apply(
                "suppression windows",
                Window.<KV<String, Alert>>into(FixedWindows.of(analyzer.getAlertSuppression()))
                    .triggering(
                        Repeatedly.forever(
                            AfterWatermark.pastEndOfWindow()
                                .withEarlyFirings(AfterPane.elementCountAtLeast(1))))
                    .withAllowedLateness(Duration.ZERO)
                    .discardingFiredPanes())
            .apply("suppression gbk", GroupByKey.<String, Alert>create())
            .apply(ParDo.of(new RateLimitSuppressor()));
      }
    };
  }

  /**
   * Get analysis identifier
   *
   * @return Identifier string
   */
  public String getIdentifier() {
    return identifier;
  }

  /**
   * Get monitored resource value
   *
   * @return Monitored resource value
   */
  public String getMonitoredResource() {
    return monitoredResource;
  }

  /**
   * Set input event filter
   *
   * @param filter Filter for event stream, should including keying selector
   * @return RateLimitAnalyzer for chaining
   */
  public RateLimitAnalyzer setFilter(EventFilter filter) {
    this.filter = filter;
    return this;
  }

  /**
   * Get configured event filter
   *
   * @return Configured event filter
   */
  public EventFilter getFilter() {
    return filter;
  }

  /**
   * Set alert suppression time window length
   *
   * @param suppressLen Length in seconds of alert suppression window
   * @return RateLimitAnalyzer for chaining
   */
  public RateLimitAnalyzer setAlertSuppression(Long suppressLen) {
    suppressLength = Duration.standardSeconds(suppressLen);
    return this;
  }

  /**
   * Get alert suppression length
   *
   * @return Alert suppression window length
   */
  public Duration getAlertSuppression() {
    return suppressLength;
  }

  /**
   * Set alerting criteria
   *
   * @param count Count at or after which alerts will be created
   * @param severity Alert severity
   * @return RateLimitAnalyzer for chaining
   */
  public RateLimitAnalyzer setAlertCriteria(Long count, Alert.AlertSeverity severity) {
    limitCount = count;
    this.severity = severity;
    return this;
  }

  /**
   * Get alert criteria limit value
   *
   * @return Count used in analysis criteria
   */
  public Long getAlertCriteriaLimit() {
    return limitCount;
  }

  /**
   * Get alert severity
   *
   * @return Severity that will be applied to alerts
   */
  public Alert.AlertSeverity getAlertCriteriaSeverity() {
    return severity;
  }

  /**
   * Set analysis window properties
   *
   * @param windowLen Analysis window length in seconds
   * @param slideLen Seconds after which window slides
   * @return RateLimitAnalyzer for chaining
   */
  public RateLimitAnalyzer setAnalysisWindow(Long windowLen, Long slideLen) {
    windowLength = Duration.standardSeconds(windowLen);
    windowSlideLength = Duration.standardSeconds(slideLen);
    return this;
  }

  /**
   * Get analysis window length
   *
   * @return Analysis window length
   */
  public Duration getWindowLength() {
    return windowLength;
  }

  /**
   * Get analysis window sliding interval
   *
   * @return Analysis window sliding interval
   */
  public Duration getWindowSlideLength() {
    return windowSlideLength;
  }

  /**
   * Create new RateLimitAnalyzer
   *
   * @param identifier Identifier for this particular analyzer instance
   */
  public RateLimitAnalyzer(String identifier, String monitoredResource) {
    this.identifier = identifier;
    this.monitoredResource = monitoredResource;
  }
}
