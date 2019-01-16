package com.mozilla.secops.httprequest;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.Stats;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
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
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.Keys;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.View;
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
import org.apache.beam.sdk.values.TypeDescriptors;
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
   * <p>This function discards events that are not considered HTTP requests.
   */
  public static class Parse extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private final Boolean emitEventTimestamps;
    private String stackdriverProjectFilter;

    /**
     * Only emit parsed Stackdriver events that are associated with specified project
     *
     * @param project Project name
     */
    public void withStackdriverProjectFilter(String project) {
      stackdriverProjectFilter = project;
    }

    public Parse(Boolean emitEventTimestamps) {
      this.emitEventTimestamps = emitEventTimestamps;
    }

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter =
          new EventFilter().setWantUTC(true).setOutputWithTimestamp(emitEventTimestamps);
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GLB));

      ParserDoFn fn = new ParserDoFn();
      if (stackdriverProjectFilter != null) {
        fn = fn.withStackdriverProjectFilter(stackdriverProjectFilter);
      }
      return col.apply(ParDo.of(fn)).apply(EventFilter.getTransform(filter));
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

  /** Window events into fixed one minute windows with early firings */
  public static class WindowForFixedFireEarly
      extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<Event> expand(PCollection<Event> input) {
      return input.apply(
          Window.<Event>into(FixedWindows.of(Duration.standardMinutes(1)))
              .triggering(
                  Repeatedly.forever(
                      AfterWatermark.pastEndOfWindow()
                          .withEarlyFirings(
                              AfterProcessingTime.pastFirstElementInPane()
                                  .plusDelayOf(Duration.standardSeconds(5L)))))
              .withAllowedLateness(Duration.ZERO)
              .accumulatingFiredPanes());
    }
  }

  /**
   * Additional event preprocessing for {@link HTTPRequest} analysis components
   *
   * <p>DoFn to apply additional processing to the event stream prior to events being pushed into
   * the analysis components of the pipeline.
   */
  public static class Preprocessor extends DoFn<Event, Event> {
    private static final long serialVersionUID = 1L;

    private String[] filterRequestPath;

    /** Static initializer for {@link Preprocessor} */
    public Preprocessor() {
      filterRequestPath = null;
    }

    /**
     * Static initializer for {@link Preprocessor}
     *
     * @param options Pipeline options
     */
    public Preprocessor(HTTPRequestOptions options) {
      this();
      filterRequestPath = options.getFilterRequestPath();
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
      if (filterRequestPath == null) {
        c.output(c.element());
        return;
      }
      Event e = c.element();
      GLB g = e.getPayload();
      Integer status = g.getStatus();
      if (status == null || status != 200) {
        // Always emit errors
        c.output(e);
        return;
      }
      String method = g.getRequestMethod();
      URL u = g.getParsedUrl();
      if (u == null) {
        c.output(e);
        return;
      }
      String path = u.getPath();
      if (path == null) {
        c.output(e);
        return;
      }
      for (String s : filterRequestPath) {
        String[] parts = s.split(":");
        if (parts.length != 2) {
          throw new IllegalArgumentException(
              "invalid format for filter path, must be <method>:<path>");
        }
        if (parts[0].equals(method) && parts[1].equals(path)) {
          // Match, so just drop the event
          return;
        }
      }
      c.output(e);
    }
  }

  /**
   * Composite transform which given a set of windowed {@link Event} types, emits a set of {@link
   * KV} objects where the key is the source address of the request and the value is the number of
   * requests for that source within the window.
   */
  public static class CountInWindow
      extends PTransform<PCollection<Event>, PCollection<KV<String, Long>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Long>> expand(PCollection<Event> col) {
      class GetSourceAddress extends DoFn<Event, String> {
        private static final long serialVersionUID = 1L;

        @ProcessElement
        public void processElement(ProcessContext c) {
          GLB g = c.element().getPayload();
          c.output(g.getSourceAddress());
        }
      }

      return col.apply(ParDo.of(new GetSourceAddress())).apply(Count.<String>perElement());
    }
  }

  /**
   * Composite transform which given a set of windowed {@link Event} types, emits a set of {@link
   * KV} objects where the key is the source address of the request and the value is the number of
   * client errors for that source within the window.
   */
  public static class CountErrorsInWindow
      extends PTransform<PCollection<Event>, PCollection<KV<String, Long>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Long>> expand(PCollection<Event> col) {
      class GetAddressErrors extends DoFn<Event, String> {
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
      }

      return col.apply(ParDo.of(new GetAddressErrors())).apply(Count.<String>perElement());
    }
  }

  /**
   * {@link DoFn} to analyze key value pairs of source address and error count and emit a {@link
   * Alert} for each address that exceeds the maximum client error rate
   */
  public static class ErrorRateAnalysis extends DoFn<KV<String, Long>, Alert> {
    private static final long serialVersionUID = 1L;
    private final Long maxErrorRate;

    /**
     * Static initializer for {@link ErrorRateAnalysis}
     *
     * @param maxErrorRate Maximum client error rate per window
     */
    public ErrorRateAnalysis(Long maxErrorRate) {
      this.maxErrorRate = maxErrorRate;
    }

    @ProcessElement
    public void processElement(ProcessContext c, BoundedWindow w) {
      if (c.element().getValue() <= maxErrorRate) {
        return;
      }
      Alert a = new Alert();
      a.setCategory("httprequest");
      a.addMetadata("category", "error_rate");
      a.addMetadata("sourceaddress", c.element().getKey());
      a.addMetadata("error_count", c.element().getValue().toString());
      a.addMetadata("error_threshold", maxErrorRate.toString());
      a.addMetadata("window_timestamp", (new DateTime(w.maxTimestamp())).toString());
      c.output(a);
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

    /**
     * Static initializer for {@link EndpointAbuseAnalysis}
     *
     * @param options Pipeline options
     */
    public EndpointAbuseAnalysis(HTTPRequestOptions options) {
      log = LoggerFactory.getLogger(EndpointAbuseAnalysis.class);
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
                      if (sourceAddress == null || requestMethod == null) {
                        return;
                      }
                      URL u = g.getParsedUrl();
                      if (u == null) {
                        return;
                      }
                      ArrayList<String> v = new ArrayList<>();
                      v.add(requestMethod);
                      v.add(u.getPath());
                      c.output(KV.of(sourceAddress, v));
                    }
                  }))
          .apply(GroupByKey.<String, ArrayList<String>>create())
          .apply(
              "analyze per-client",
              ParDo.of(
                  new DoFn<KV<String, Iterable<ArrayList<String>>>, Alert>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c, BoundedWindow w) {
                      String remoteAddress = c.element().getKey();
                      Iterable<ArrayList<String>> paths = c.element().getValue();

                      // Take a look at the first entry in the data set and see if it
                      // corresponds to anything we have in the endpoints map. If so, look at
                      // the rest of the requests in the window to determine variance and
                      // if the noted threshold has been exceeded.
                      Integer foundThreshold = null;
                      String compareMethod = null;
                      String comparePath = null;
                      int count = 0;
                      for (ArrayList<String> i : paths) {
                        if (foundThreshold == null) {
                          foundThreshold = getEndpointThreshold(i.get(1), i.get(0));
                          compareMethod = i.get(0);
                          comparePath = i.get(1);
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
                        log.info("{}: emitting alert for {}", w.toString(), remoteAddress);
                        Alert a = new Alert();
                        a.setCategory("httprequest");
                        a.addMetadata("category", "endpoint_abuse");
                        a.addMetadata("sourceaddress", remoteAddress);
                        a.addMetadata("endpoint", comparePath);
                        a.addMetadata("method", compareMethod);
                        a.addMetadata("count", Integer.toString(count));
                        a.addMetadata(
                            "window_timestamp", (new DateTime(w.maxTimestamp())).toString());
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
   * across a set of KV objects as returned by {@link CountInWindow}.
   */
  public static class ThresholdAnalysis
      extends PTransform<PCollection<KV<String, Long>>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final Double thresholdModifier;
    private final Double requiredMinimumAverage;
    private final Long requiredMinimumClients;
    private final Double clampThresholdMaximum;
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
    public PCollection<Alert> expand(PCollection<KV<String, Long>> col) {
      if (natView == null) {
        // If natView was not set then we just create an empty view for use as the side input
        natView =
            col.getPipeline()
                .apply(
                    Create.empty(
                        TypeDescriptors.kvs(TypeDescriptors.strings(), TypeDescriptors.booleans())))
                .apply(View.<String, Boolean>asMap());
      }

      PCollectionView<Long> uniqueClients =
          col.apply(Keys.<String>create())
              .apply(
                  "Unique client count",
                  Combine.globally(Count.<String>combineFn()).withoutDefaults().asSingletonView());

      PCollection<Long> counts =
          col.apply(
              "Extract counts",
              ParDo.of(
                  new DoFn<KV<String, Long>, Long>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      c.output(c.element().getValue());
                    }
                  }));
      final PCollectionView<Stats.StatsOutput> wStats = Stats.getView(counts);

      PCollection<Alert> ret =
          col.apply(
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
                            log.info(
                                "{}: emitting alert for {}", w.toString(), c.element().getKey());
                            Alert a = new Alert();
                            a.setCategory("httprequest");
                            a.addMetadata("category", "threshold_analysis");
                            a.addMetadata("sourceaddress", c.element().getKey());
                            a.addMetadata("mean", sOutput.getMean().toString());
                            a.addMetadata("count", c.element().getValue().toString());
                            a.addMetadata("threshold_modifier", thresholdModifier.toString());
                            a.addMetadata(
                                "window_timestamp", (new DateTime(w.maxTimestamp())).toString());
                            c.output(a);
                          }
                        }
                      })
                  .withSideInputs(wStats, natView, uniqueClients));
      return ret;
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

    @Description("Filter any Stackdriver events that do not match project name")
    String getStackdriverProjectFilter();

    void setStackdriverProjectFilter(String value);

    @Description(
        "Endpoint abuse analysis paths for monitoring (multiple allowed); e.g., threshold:method:/path")
    String[] getEndpointAbusePath();

    void setEndpointAbusePath(String[] value);

    @Description("Filter successful requests for path before analysis; e.g., method:/path")
    String[] getFilterRequestPath();

    void setFilterRequestPath(String[] value);
  }

  private static void runHTTPRequest(HTTPRequestOptions options) {
    Pipeline p = Pipeline.create(options);

    Parse pw = new Parse(false);
    if (options.getStackdriverProjectFilter() != null) {
      pw.withStackdriverProjectFilter(options.getStackdriverProjectFilter());
    }
    PCollection<Event> events =
        p.apply("input", options.getInputType().read(p, options))
            .apply("parse", pw)
            .apply("preprocess", ParDo.of(new Preprocessor(options)));

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
                  .apply("per-client", new CountInWindow())
                  .apply("threshold analysis", new ThresholdAnalysis(options, natView))
                  .apply("output format", ParDo.of(new AlertFormatter(options))));
    }

    if (options.getEnableErrorRateAnalysis()) {
      resultsList =
          resultsList.and(
              fwEvents
                  .apply("cerr per client", new CountErrorsInWindow())
                  .apply(
                      "error rate analysis",
                      ParDo.of(new ErrorRateAnalysis(options.getMaxClientErrorRate())))
                  .apply("output format", ParDo.of(new AlertFormatter(options))));
    }

    if (options.getEnableEndpointAbuseAnalysis()) {
      resultsList =
          resultsList.and(
              efEvents
                  .apply("endpoint abuse analysis", new EndpointAbuseAnalysis(options))
                  .apply("output format", ParDo.of(new AlertFormatter(options))));
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
