package com.mozilla.secops.httprequest;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.Stats;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.GLB;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import java.io.Serializable;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.state.StateSpec;
import org.apache.beam.sdk.state.StateSpecs;
import org.apache.beam.sdk.state.ValueState;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.Keys;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link HTTPRequest} describes and implements a Beam pipeline for analysis of HTTP requests using
 * log data.
 */
public class HTTPRequest implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Composite transform to parse a {@link PCollection} containing events as strings and emit a
   * {@link PCollection} of {@link Event} objects.
   *
   * <p>This transform currently discards events that are not {@link GLB} events.
   */
  public static class Parse extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private final Boolean emitEventTimestamps;
    private final String stackdriverProjectFilter;
    private final String[] filterRequestPath;

    /**
     * Static initializer for {@link Parse} transform
     *
     * @param options Pipeline options
     */
    public Parse(HTTPRequestOptions options) {
      emitEventTimestamps = options.getUseEventTimestamp();
      stackdriverProjectFilter = options.getStackdriverProjectFilter();
      filterRequestPath = options.getFilterRequestPath();
    }

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter =
          new EventFilter().setWantUTC(true).setOutputWithTimestamp(emitEventTimestamps);
      EventFilterRule rule = new EventFilterRule().wantSubtype(Payload.PayloadType.GLB);
      if (stackdriverProjectFilter != null) {
        rule.wantStackdriverProject(stackdriverProjectFilter);
      }
      if (filterRequestPath != null) {
        for (String s : filterRequestPath) {
          String[] parts = s.split(":");
          if (parts.length != 2) {
            throw new IllegalArgumentException(
                "invalid format for filter path, must be <method>:<path>");
          }
          rule.except(
              new EventFilterRule()
                  .wantSubtype(Payload.PayloadType.GLB)
                  .addPayloadFilter(
                      new EventFilterPayload(GLB.class)
                          .withStringMatch(
                              EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, parts[0])
                          .withStringMatch(
                              EventFilterPayload.StringProperty.GLB_URLREQUESTPATH, parts[1])
                          // XXX This should likely be a range (e.g., >= 200 < 300)
                          .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200)));
        }
      }
      filter.addRule(rule);
      return col.apply(ParDo.of(new ParserDoFn().withInlineEventFilter(filter)));
    }
  }

  /** Window events into fixed one minute windows */
  public static class WindowForFixed extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<Event> expand(PCollection<Event> input) {
      return input.apply(Window.<Event>into(FixedWindows.of(Duration.standardMinutes(1))));
    }
  }

  /**
   * Window events into fixed ten minute windows with early firings
   *
   * <p>Panes are accumulated.
   */
  public static class WindowForFixedFireEarly
      extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<Event> expand(PCollection<Event> input) {
      return input.apply(
          Window.<Event>into(FixedWindows.of(Duration.standardMinutes(10)))
              .triggering(
                  Repeatedly.forever(
                      AfterWatermark.pastEndOfWindow()
                          .withEarlyFirings(
                              AfterProcessingTime.pastFirstElementInPane()
                                  .plusDelayOf(Duration.standardSeconds(10L)))))
              .withAllowedLateness(Duration.ZERO)
              .accumulatingFiredPanes());
    }
  }

  /** Transform for analysis of error rates per client within a given window. */
  public static class ErrorRateAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final Long maxErrorRate;
    private final String monitoredResource;

    /**
     * Static initializer for {@link ErrorRateAnalysis}
     *
     * @param maxErrorRate Maximum client error rate per window
     */
    public ErrorRateAnalysis(HTTPRequestOptions options) {
      maxErrorRate = options.getMaxClientErrorRate();
      monitoredResource = options.getMonitoredResourceIndicator();
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      return input
          .apply(
              "isolate client errors",
              ParDo.of(
                  new DoFn<Event, String>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      GLB g = c.element().getPayload();
                      Integer status = g.getStatus();
                      if (status == null) {
                        return;
                      }
                      if (status >= 400 && status < 500) {
                        c.output(g.getSourceAddress());
                      }
                    }
                  }))
          .apply(Count.<String>perElement())
          .apply(
              "per-client error rate analysis",
              ParDo.of(
                  new DoFn<KV<String, Long>, Alert>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c, BoundedWindow w) {
                      if (c.element().getValue() <= maxErrorRate) {
                        return;
                      }
                      Alert a = new Alert();
                      a.setSummary(
                          String.format(
                              "%s httprequest error_rate %s %d",
                              monitoredResource, c.element().getKey(), c.element().getValue()));
                      a.setCategory("httprequest");
                      a.addMetadata("category", "error_rate");
                      a.addMetadata("sourceaddress", c.element().getKey());
                      a.addMetadata("error_count", c.element().getValue().toString());
                      a.addMetadata("error_threshold", maxErrorRate.toString());
                      a.addMetadata(
                          "window_timestamp", (new DateTime(w.maxTimestamp())).toString());
                      if (!a.hasCorrectFields()) {
                        throw new IllegalArgumentException("alert has invalid field configuration");
                      }
                      c.output(a);
                    }
                  }));
    }
  }

  /**
   * Transform for detection of a single source endpoint making excessive requests of a specific
   * endpoint path solely.
   *
   * <p>Generates alerts where the request profile violates path thresholds specified in the
   * endpointAbusePath pipeline option configuration.
   */
  public static class EndpointAbuseAnalysis
      extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private Logger log;

    private final Map<String[], Integer> endpoints;
    private final String monitoredResource;

    /**
     * Static initializer for {@link EndpointAbuseAnalysis}
     *
     * @param options Pipeline options
     */
    public EndpointAbuseAnalysis(HTTPRequestOptions options) {
      log = LoggerFactory.getLogger(EndpointAbuseAnalysis.class);

      monitoredResource = options.getMonitoredResourceIndicator();

      endpoints = new HashMap<String[], Integer>();
      for (String endpoint : options.getEndpointAbusePath()) {
        String[] parts = endpoint.split(":");
        if (parts.length != 3) {
          throw new IllegalArgumentException(
              "invalid format for abuse endpoint path, must be <int>:<method>:<path>");
        }
        String k[] = new String[2];
        k[0] = parts[1];
        k[1] = parts[2];
        endpoints.put(k, new Integer(parts[0]));
      }
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      return input
          .apply(
              "filter inapplicable requests",
              ParDo.of(
                  new DoFn<Event, KV<String, ArrayList<String>>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      GLB g = c.element().getPayload();

                      String sourceAddress = g.getSourceAddress();
                      String requestMethod = g.getRequestMethod();
                      String userAgent = g.getUserAgent();
                      if (sourceAddress == null || requestMethod == null) {
                        return;
                      }
                      if (userAgent == null) {
                        userAgent = "unknown";
                      }
                      URL u = g.getParsedUrl();
                      if (u == null) {
                        return;
                      }
                      ArrayList<String> v = new ArrayList<>();
                      v.add(requestMethod);
                      v.add(u.getPath());
                      v.add(userAgent);
                      c.output(KV.of(sourceAddress, v));
                    }
                  }))
          .apply(GroupByKey.<String, ArrayList<String>>create())
          .apply(
              "analyze per-client",
              ParDo.of(
                  new DoFn<KV<String, Iterable<ArrayList<String>>>, Alert>() {
                    private static final long serialVersionUID = 1L;

                    @StateId("counter")
                    private final StateSpec<ValueState<Integer>> counterState = StateSpecs.value();

                    @ProcessElement
                    public void processElement(
                        ProcessContext c,
                        BoundedWindow w,
                        @StateId("counter") ValueState<Integer> counter) {
                      String remoteAddress = c.element().getKey();
                      Iterable<ArrayList<String>> paths = c.element().getValue();

                      // Take a look at the first entry in the data set and see if it
                      // corresponds to anything we have in the endpoints map. If so, look at
                      // the rest of the requests in the window to determine variance and
                      // if the noted threshold has been exceeded.
                      Integer foundThreshold = null;
                      String compareMethod = null;
                      String comparePath = null;
                      String userAgent = null;
                      int count = 0;
                      for (ArrayList<String> i : paths) {
                        if (foundThreshold == null) {
                          foundThreshold = getEndpointThreshold(i.get(1), i.get(0));
                          compareMethod = i.get(0);
                          comparePath = i.get(1);
                          userAgent = i.get(2);
                        } else {
                          if (!(compareMethod.equals(i.get(0)))
                              || !(comparePath.equals(i.get(1)))) {
                            // Variance in requests in-window
                            return;
                          }
                        }
                        if (foundThreshold == null) {
                          // Entry wasn't in monitor map, so just ignore this client
                          //
                          // XXX This should be improved to determine when to ignore based on
                          // perhaps a weighting heuristic if most of the requests are
                          // applicable.
                          return;
                        }
                        count++;
                      }
                      if (count >= foundThreshold) {
                        // If we already have counter state for this key, compare it against what
                        // the path count was. If they are the same, this is likely a
                        // duplicate associated with the window closing so we just
                        // ignore it.
                        Integer rCount = counter.read();
                        if (rCount != null && rCount.equals(count)) {
                          log.info("suppressing additional in-window alert for {}", remoteAddress);
                          return;
                        }
                        counter.write(count);

                        if (rCount != null && rCount < count) {
                          // If we had counter state for this key and it is less than the
                          // path component count, this is a supplemental pane with more
                          // requests in it.
                          //
                          // Generate another alert, but decrement the count value in the
                          // alert to reflect the delta between what we have already alerted
                          // on and this new alert.
                          count = count - rCount;
                          log.info(
                              "{}: supplemental alert for {} {}",
                              w.toString(),
                              remoteAddress,
                              count);
                        } else {
                          log.info(
                              "{}: emitting alert for {} {}", w.toString(), remoteAddress, count);
                        }

                        Alert a = new Alert();
                        a.setSummary(
                            String.format(
                                "%s httprequest endpoint_abuse %s %s %s %d",
                                monitoredResource,
                                remoteAddress,
                                compareMethod,
                                comparePath,
                                count));
                        a.setCategory("httprequest");
                        a.addMetadata("category", "endpoint_abuse");
                        a.addMetadata("sourceaddress", remoteAddress);
                        a.addMetadata("endpoint", comparePath);
                        a.addMetadata("method", compareMethod);
                        a.addMetadata("count", Integer.toString(count));
                        a.addMetadata("useragent", userAgent);
                        a.addMetadata(
                            "window_timestamp", (new DateTime(w.maxTimestamp())).toString());
                        if (!a.hasCorrectFields()) {
                          throw new IllegalArgumentException(
                              "alert has invalid field configuration");
                        }
                        c.output(a);
                      }
                    }
                  }));
    }

    private Integer getEndpointThreshold(String path, String method) {
      for (Map.Entry<String[], Integer> entry : endpoints.entrySet()) {
        String k[] = entry.getKey();
        if (method.equals(k[0]) && path.equals(k[1])) {
          return entry.getValue();
        }
      }
      return null;
    }
  }

  /**
   * Composite transform that conducts threshold analysis using the configured threshold modifier
   */
  public static class ThresholdAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final Double thresholdModifier;
    private final Double requiredMinimumAverage;
    private final Long requiredMinimumClients;
    private final Double clampThresholdMaximum;
    private final String monitoredResource;
    private PCollectionView<Map<String, Boolean>> natView = null;

    private Logger log;

    /**
     * Static initializer for {@link ThresholdAnalysis}.
     *
     * @param options {@link HTTPRequestOptions}
     */
    public ThresholdAnalysis(HTTPRequestOptions options) {
      this.thresholdModifier = options.getAnalysisThresholdModifier();
      this.requiredMinimumAverage = options.getRequiredMinimumAverage();
      this.requiredMinimumClients = options.getRequiredMinimumClients();
      this.clampThresholdMaximum = options.getClampThresholdMaximum();
      this.monitoredResource = options.getMonitoredResourceIndicator();
      log = LoggerFactory.getLogger(ThresholdAnalysis.class);
    }

    /**
     * Static initializer for {@link ThresholdAnalysis}.
     *
     * @param options {@link HTTPRequestOptions}
     * @param natView Use {@link DetectNat} view during threshold analysis
     */
    public ThresholdAnalysis(
        HTTPRequestOptions options, PCollectionView<Map<String, Boolean>> natView) {
      this(options);
      this.natView = natView;
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      if (natView == null) {
        // If natView was not set then we just create an empty view for use as the side input
        natView = DetectNat.getEmptyView(col.getPipeline());
      }

      // Count per source address
      PCollection<KV<String, Long>> clientCounts =
          col.apply(
                  "calculate per client count",
                  ParDo.of(
                      new DoFn<Event, String>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c) {
                          GLB g = c.element().getPayload();
                          c.output(g.getSourceAddress());
                        }
                      }))
              .apply(Count.<String>perElement());

      // Calculate the number of unique clients in the collection
      PCollectionView<Long> uniqueClients =
          clientCounts
              .apply(Keys.<String>create())
              .apply(
                  "unique client count",
                  Combine.globally(Count.<String>combineFn()).withoutDefaults().asSingletonView());

      // For each client, extract the request count
      PCollection<Long> counts =
          clientCounts.apply(
              "extract counts",
              ParDo.of(
                  new DoFn<KV<String, Long>, Long>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      c.output(c.element().getValue());
                    }
                  }));
      // Obtain statistics on the client count population for use as a side input
      final PCollectionView<Stats.StatsOutput> wStats = Stats.getView(counts);

      return clientCounts.apply(
          ParDo.of(
                  new DoFn<KV<String, Long>, Alert>() {
                    private static final long serialVersionUID = 1L;

                    private Boolean warningLogged;
                    private Boolean clampMaximumLogged;
                    private Boolean statsLogged;

                    @StartBundle
                    public void startBundle() {
                      warningLogged = false;
                      clampMaximumLogged = false;
                      statsLogged = false;
                    }

                    @ProcessElement
                    public void processElement(ProcessContext c, BoundedWindow w) {
                      Stats.StatsOutput sOutput = c.sideInput(wStats);
                      Long uc = c.sideInput(uniqueClients);
                      Map<String, Boolean> nv = c.sideInput(natView);

                      Double cMean = sOutput.getMean();
                      if (!statsLogged) {
                        log.info(
                            "{}: statistics: mean/{} unique_clients/{} threshold/{}",
                            w.toString(),
                            cMean,
                            uc,
                            cMean * thresholdModifier);
                        statsLogged = true;
                      }

                      if (uc < requiredMinimumClients) {
                        if (!warningLogged) {
                          log.warn(
                              "{}: ignoring events as window does not meet minimum clients",
                              w.toString());
                          warningLogged = true;
                        }
                        return;
                      }

                      if (cMean < requiredMinimumAverage) {
                        if (!warningLogged) {
                          log.warn(
                              "{}: ignoring events as window does not meet minimum average",
                              w.toString());
                          warningLogged = true;
                        }
                        return;
                      }

                      if ((clampThresholdMaximum != null) && (cMean > clampThresholdMaximum)) {
                        if (!clampMaximumLogged) {
                          log.info(
                              "{}: clamping calculated mean {} to maximum {}",
                              w.toString(),
                              cMean,
                              clampThresholdMaximum);
                          clampMaximumLogged = true;
                        }
                        cMean = clampThresholdMaximum;
                      }

                      if (c.element().getValue() >= (cMean * thresholdModifier)) {
                        Boolean isNat = nv.get(c.element().getKey());
                        if (isNat != null && isNat) {
                          log.info(
                              "{}: detectnat: skipping result emission for {}",
                              w.toString(),
                              c.element().getKey());
                          return;
                        }
                        log.info("{}: emitting alert for {}", w.toString(), c.element().getKey());
                        Alert a = new Alert();
                        a.setSummary(
                            String.format(
                                "%s httprequest threshold_analysis %s %d",
                                monitoredResource, c.element().getKey(), c.element().getValue()));
                        a.setCategory("httprequest");
                        a.addMetadata("category", "threshold_analysis");
                        a.addMetadata("sourceaddress", c.element().getKey());
                        a.addMetadata("mean", sOutput.getMean().toString());
                        a.addMetadata("count", c.element().getValue().toString());
                        a.addMetadata("threshold_modifier", thresholdModifier.toString());
                        a.addMetadata(
                            "window_timestamp", (new DateTime(w.maxTimestamp())).toString());
                        if (!a.hasCorrectFields()) {
                          throw new IllegalArgumentException(
                              "alert has invalid field configuration");
                        }
                        c.output(a);
                      }
                    }
                  })
              .withSideInputs(wStats, natView, uniqueClients));
    }
  }

  /** Runtime options for {@link HTTPRequest} pipeline. */
  public interface HTTPRequestOptions extends PipelineOptions, InputOptions, OutputOptions {
    @Description("Enable threshold analysis")
    @Default.Boolean(false)
    Boolean getEnableThresholdAnalysis();

    void setEnableThresholdAnalysis(Boolean value);

    @Description("Enable error rate analysis")
    @Default.Boolean(false)
    Boolean getEnableErrorRateAnalysis();

    void setEnableErrorRateAnalysis(Boolean value);

    @Description("Enable endpoint abuse analysis")
    @Default.Boolean(false)
    Boolean getEnableEndpointAbuseAnalysis();

    void setEnableEndpointAbuseAnalysis(Boolean value);

    @Description("Analysis threshold modifier")
    @Default.Double(75.0)
    Double getAnalysisThresholdModifier();

    void setAnalysisThresholdModifier(Double value);

    @Description(
        "Required minimum average number of requests per client/window for threshold analysis")
    @Default.Double(5.0)
    Double getRequiredMinimumAverage();

    void setRequiredMinimumAverage(Double value);

    @Description("Required minimum number of unique clients per window for threshold analysis")
    @Default.Long(5L)
    Long getRequiredMinimumClients();

    void setRequiredMinimumClients(Long value);

    @Description(
        "Restrict maximum calculated average for threshold analysis; clamps to value if exceeded")
    Double getClampThresholdMaximum();

    void setClampThresholdMaximum(Double value);

    @Description("Maximum permitted client error rate per window")
    @Default.Long(30L)
    Long getMaxClientErrorRate();

    void setMaxClientErrorRate(Long value);

    @Description("Enable NAT detection for threshold analysis")
    @Default.Boolean(false)
    Boolean getNatDetection();

    void setNatDetection(Boolean value);

    @Description("Only inspect Stackdriver events generated for specified project identifier")
    String getStackdriverProjectFilter();

    void setStackdriverProjectFilter(String value);

    @Description(
        "Endpoint abuse analysis paths for monitoring (multiple allowed); e.g., threshold:method:/path")
    String[] getEndpointAbusePath();

    void setEndpointAbusePath(String[] value);

    @Description("Filter successful requests for path before analysis; e.g., method:/path")
    String[] getFilterRequestPath();

    void setFilterRequestPath(String[] value);

    @Description("Use timestamp parsed from event instead of timestamp set in input transform")
    @Default.Boolean(false)
    Boolean getUseEventTimestamp();

    void setUseEventTimestamp(Boolean value);
  }

  private static void runHTTPRequest(HTTPRequestOptions options) {
    Pipeline p = Pipeline.create(options);

    PCollection<Event> events =
        p.apply("input", options.getInputType().read(p, options))
            .apply("parse", new Parse(options));

    PCollection<Event> fwEvents = events.apply("window for fixed", new WindowForFixed());
    PCollection<Event> efEvents =
        events.apply("window for fixed fire early", new WindowForFixedFireEarly());

    PCollectionView<Map<String, Boolean>> natView = null;
    if (options.getNatDetection()) {
      natView = DetectNat.getView(fwEvents);
    }

    PCollectionList<String> resultsList = PCollectionList.empty(p);

    if (options.getEnableThresholdAnalysis()) {
      resultsList =
          resultsList.and(
              fwEvents
                  .apply("threshold analysis", new ThresholdAnalysis(options, natView))
                  .apply("output format", ParDo.of(new AlertFormatter(options))));
    }

    if (options.getEnableErrorRateAnalysis()) {
      resultsList =
          resultsList.and(
              fwEvents
                  .apply("error rate analysis", new ErrorRateAnalysis(options))
                  .apply("output format", ParDo.of(new AlertFormatter(options))));
    }

    if (options.getEnableEndpointAbuseAnalysis()) {
      efEvents
          .apply("endpoint abuse analysis", new EndpointAbuseAnalysis(options))
          .apply("output format", ParDo.of(new AlertFormatter(options)))
          .apply("output", OutputOptions.compositeOutput(options));
    }

    PCollection<String> results = resultsList.apply(Flatten.<String>pCollections());
    results.apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) {
    PipelineOptionsFactory.register(HTTPRequestOptions.class);
    HTTPRequestOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(HTTPRequestOptions.class);
    runHTTPRequest(options);
  }
}
