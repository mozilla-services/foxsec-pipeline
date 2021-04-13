package com.mozilla.secops.httprequest;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.FileUtil;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.SourceCorrelation;
import com.mozilla.secops.Stats;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.httprequest.HTTPRequestMetrics.HeuristicMetrics;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.input.InputElement;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Distinct;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Filter;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.SerializableFunction;
import org.apache.beam.sdk.transforms.Values;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Sessions;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.apache.beam.sdk.values.PCollectionTuple;
import org.apache.beam.sdk.values.PCollectionView;
import org.apache.beam.sdk.values.TupleTag;
import org.apache.beam.sdk.values.TupleTagList;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link HTTPRequest} describes and implements a Beam pipeline for analysis of HTTP requests using
 * log data.
 */
public class HTTPRequest implements Serializable {
  private static final long serialVersionUID = 1L;

  private static transient ConcurrentHashMap<String, HTTPRequestToggles> toggleCache =
      new ConcurrentHashMap<>();

  /**
   * Add an entry to the HTTPRequest toggle cache
   *
   * <p>For use in tests, should not be called under normal use.
   *
   * @param name Cache key name
   * @param entry Cache entry
   */
  public static void addToggleCacheEntry(String name, HTTPRequestToggles entry) {
    toggleCache.put(name, entry);
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
   * Key requests for session analysis and window into sessions
   *
   * <p>Windows are configured to fire early every 10 seconds, and accumulate panes.
   */
  public static class KeyAndWindowForSessionsFireEarly
      extends PTransform<PCollection<Event>, PCollection<KV<String, ArrayList<String>>>> {
    private static final long serialVersionUID = 1L;

    private final Long gapDurationMinutes;
    private final Long paneFiringDelaySeconds = 10L;

    public KeyAndWindowForSessionsFireEarly(Long gapDurationMinutes) {
      this.gapDurationMinutes = gapDurationMinutes;
    }

    @Override
    public PCollection<KV<String, ArrayList<String>>> expand(PCollection<Event> input) {
      return input
          .apply(
              "key for session analysis",
              ParDo.of(
                  new DoFn<Event, KV<String, ArrayList<String>>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Normalized n = c.element().getNormalized();

                      // Don't include requests that involve a server side error
                      if ((n.getRequestStatus() == null) || (n.getRequestStatus() >= 500)) {
                        return;
                      }

                      String sourceAddress = n.getSourceAddress();
                      String requestMethod = n.getRequestMethod();
                      String userAgent = n.getUserAgent();
                      String rpath = n.getUrlRequestPath();
                      String url = n.getRequestUrl();
                      String status = String.valueOf(n.getRequestStatus());
                      if (sourceAddress == null
                          || requestMethod == null
                          || rpath == null
                          || url == null) {
                        return;
                      }
                      if (userAgent == null) {
                        userAgent = "unknown";
                      }
                      String eTime = c.element().getTimestamp().toString();
                      ArrayList<String> v = new ArrayList<>();
                      v.add(requestMethod);
                      v.add(rpath);
                      v.add(userAgent);
                      v.add(eTime);
                      v.add(url);
                      v.add(status);
                      c.output(KV.of(sourceAddress, v));
                    }
                  }))
          .apply(
              "window for sessions",
              Window.<KV<String, ArrayList<String>>>into(
                      Sessions.withGapDuration(Duration.standardMinutes(gapDurationMinutes)))
                  .triggering(
                      Repeatedly.forever(
                          AfterWatermark.pastEndOfWindow()
                              .withEarlyFirings(
                                  AfterProcessingTime.pastFirstElementInPane()
                                      .plusDelayOf(
                                          Duration.standardSeconds(paneFiringDelaySeconds)))))
                  .withAllowedLateness(Duration.ZERO)
                  .accumulatingFiredPanes());
    }
  }

  /** Transform for analysis of error rates per client within a given window. */
  public static class ErrorRateAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final Long maxErrorRate;
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreExemptions;
    private final String iprepdDatastoreExemptionsProject;

    private Logger log;

    /**
     * Static initializer for {@link ErrorRateAnalysis}
     *
     * @param toggles {@link HTTPRequestToggles}
     * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
     * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
     */
    public ErrorRateAnalysis(
        HTTPRequestToggles toggles,
        Boolean enableIprepdDatastoreExemptions,
        String iprepdDatastoreExemptionsProject) {
      maxErrorRate = toggles.getMaxClientErrorRate();
      monitoredResource = toggles.getMonitoredResource();
      this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
      this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
      log = LoggerFactory.getLogger(ErrorRateAnalysis.class);
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return String.format(
          "Alert if a single source address generates more than %d 4xx errors in a "
              + "1 minute window.",
          maxErrorRate);
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
                      Normalized n = c.element().getNormalized();
                      Integer status = n.getRequestStatus();
                      if (status == null) {
                        return;
                      }
                      if (n.getSourceAddress() == null) {
                        return;
                      }
                      if (status >= 400 && status < 500) {
                        c.output(n.getSourceAddress());
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
                      a.setSubcategory("error_rate");
                      a.addMetadata(AlertMeta.Key.SOURCEADDRESS, c.element().getKey());

                      if (enableIprepdDatastoreExemptions) {
                        try {
                          IprepdIO.addMetadataIfIpIsExempt(
                              c.element().getKey(), a, iprepdDatastoreExemptionsProject);
                        } catch (IOException exc) {
                          log.error("error checking iprepd exemptions: {}", exc.getMessage());
                          return;
                        }
                      }

                      a.addMetadata(AlertMeta.Key.ERROR_COUNT, c.element().getValue().toString());
                      a.addMetadata(AlertMeta.Key.ERROR_THRESHOLD, maxErrorRate.toString());
                      a.setNotifyMergeKey(String.format("%s error_count", monitoredResource));
                      a.addMetadata(
                          AlertMeta.Key.WINDOW_TIMESTAMP,
                          (new DateTime(w.maxTimestamp())).toString());
                      if (!a.hasCorrectFields()) {
                        throw new IllegalArgumentException("alert has invalid field configuration");
                      }
                      c.output(a);
                    }
                  }));
    }
  }

  /** Transform for analysis of hard per-source request count limit within fixed window */
  public static class HardLimitAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final Long maxCount;
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreExemptions;
    private final String iprepdDatastoreExemptionsProject;
    private PCollectionView<Map<String, Boolean>> natView = null;
    private final HeuristicMetrics metrics;

    private Logger log;

    /**
     * Static initializer for {@link HardLimitAnalysis}
     *
     * @param toggles {@link HTTPRequestToggles}
     * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
     * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
     * @param natView Use {@link DetectNat} view, or null to disable
     */
    public HardLimitAnalysis(
        HTTPRequestToggles toggles,
        Boolean enableIprepdDatastoreExemptions,
        String iprepdDatastoreExemptionsProject,
        PCollectionView<Map<String, Boolean>> natView) {
      maxCount = toggles.getHardLimitRequestCount();
      monitoredResource = toggles.getMonitoredResource();
      this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
      this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
      this.natView = natView;
      log = LoggerFactory.getLogger(HardLimitAnalysis.class);
      metrics = new HeuristicMetrics(HardLimitAnalysis.class.getName());
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return String.format(
          "Alert if single source address makes more than %d requests in a 1 minute window.",
          maxCount);
    }

    /**
     * Function to be used with filter transform to filter out only ip, count pairs where the count
     * is higher than the hard limit. This is used we only need the side input when an ip address is
     * over the hard limit.
     */
    private class HasCountGreaterThan implements SerializableFunction<KV<String, Long>, Boolean> {
      private static final long serialVersionUID = 1L;

      @Override
      public Boolean apply(KV<String, Long> kv) {
        if (kv.getValue() <= maxCount) {
          return false;
        }
        return true;
      }
    }

    @Override
    @SuppressWarnings("deprecation")
    public PCollection<Alert> expand(PCollection<Event> input) {
      if (natView == null) {
        // If natView was not set then we just create an empty view for use as the side input
        natView = DetectNat.getEmptyView(input.getPipeline());
      }
      return input
          .apply(
              "extract client ip",
              ParDo.of(
                  new DoFn<Event, String>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Normalized n = c.element().getNormalized();
                      if (n.getSourceAddress() == null) {
                        return;
                      }
                      c.output(n.getSourceAddress());
                    }
                  }))
          .apply("hard limit per client count", Count.<String>perElement())
          .apply("filter clients above limit", Filter.by(new HasCountGreaterThan()))
          // Reshuffle to prevent fusion of steps with large input that do not need side input
          // with low volume step that needs side input
          .apply("force materialization of input", org.apache.beam.sdk.transforms.Reshuffle.of())
          .apply(
              "per-source hard limit analysis",
              ParDo.of(
                      new DoFn<KV<String, Long>, Alert>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c, BoundedWindow w) {
                          Map<String, Boolean> nv = c.sideInput(natView);
                          Boolean isNat = nv.get(c.element().getKey());
                          if (isNat != null && isNat) {
                            log.info(
                                "{}: detectnat: skipping result emission for {}",
                                w.toString(),
                                c.element().getKey());
                            metrics.natDetected();
                            return;
                          }
                          Alert a = new Alert();
                          a.setSummary(
                              String.format(
                                  "%s httprequest hard_limit %s %d",
                                  monitoredResource, c.element().getKey(), c.element().getValue()));
                          a.setCategory("httprequest");
                          a.setSubcategory("hard_limit");
                          a.addMetadata(AlertMeta.Key.SOURCEADDRESS, c.element().getKey());

                          try {
                            if (enableIprepdDatastoreExemptions) {
                              IprepdIO.addMetadataIfIpIsExempt(
                                  c.element().getKey(), a, iprepdDatastoreExemptionsProject);
                            }
                          } catch (IOException exc) {
                            log.error("error checking iprepd exemptions: {}", exc.getMessage());
                            return;
                          }

                          a.addMetadata(AlertMeta.Key.COUNT, c.element().getValue().toString());
                          a.addMetadata(AlertMeta.Key.REQUEST_THRESHOLD, maxCount.toString());
                          a.setNotifyMergeKey(
                              String.format("%s hard_limit_count", monitoredResource));
                          a.addMetadata(
                              AlertMeta.Key.WINDOW_TIMESTAMP,
                              (new DateTime(w.maxTimestamp())).toString());
                          if (!a.hasCorrectFields()) {
                            throw new IllegalArgumentException(
                                "alert has invalid field configuration");
                          }
                          c.output(a);
                        }
                      })
                  .withSideInputs(natView));
    }
  }

  /** Analysis to identify known bad user agents */
  public static class UserAgentBlocklistAnalysis
      extends PTransform<PCollection<Event>, PCollection<Alert>> implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreExemptions;
    private final String iprepdDatastoreExemptionsProject;
    private final String uaBlocklistPath;

    private PCollectionView<Map<String, Boolean>> natView = null;
    private final HeuristicMetrics metrics;

    private Logger log;

    /**
     * Initialize new {@link UserAgentBlocklistAnalysis}
     *
     * @param toggles {@link HTTPRequestToggles}
     * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
     * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
     * @param natView Use {@link DetectNat} view, or null to disable
     */
    public UserAgentBlocklistAnalysis(
        HTTPRequestToggles toggles,
        Boolean enableIprepdDatastoreExemptions,
        String iprepdDatastoreExemptionsProject,
        PCollectionView<Map<String, Boolean>> natView) {
      monitoredResource = toggles.getMonitoredResource();
      this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
      this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
      this.natView = natView;
      uaBlocklistPath = toggles.getUserAgentBlocklistPath();
      log = LoggerFactory.getLogger(UserAgentBlocklistAnalysis.class);
      metrics = new HeuristicMetrics(UserAgentBlocklistAnalysis.class.getName());
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return new String(
          "Alert if client makes request with user agent that matches entry in blocklist.");
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      if (natView == null) {
        // If natView was not set then we just create an empty view for use as the side input
        natView = DetectNat.getEmptyView(input.getPipeline());
      }
      return input
          .apply(
              "extract agent and source",
              ParDo.of(
                  new DoFn<Event, KV<String, String>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Normalized n = c.element().getNormalized();

                      String sourceAddress = n.getSourceAddress();
                      if (sourceAddress == null) {
                        return;
                      }

                      String ua = n.getUserAgent();
                      if (ua == null) {
                        return;
                      }
                      // As an optimization, anything resembling a Firefox user agent we will
                      // just exclude from further analysis in this transform.
                      if (ua.contains("Firefox/")) {
                        return;
                      }
                      c.output(KV.of(sourceAddress, ua));
                    }
                  }))
          .apply("distinct agent and source", Distinct.<KV<String, String>>create())
          .apply(
              "isolate matching agents",
              ParDo.of(
                  new DoFn<KV<String, String>, KV<String, String>>() {
                    private static final long serialVersionUID = 1L;

                    private Pattern uaRegex;

                    @Setup
                    public void setup() throws IOException {
                      ArrayList<String> in = FileUtil.fileReadLines(uaBlocklistPath);
                      uaRegex = Pattern.compile(String.join("|", in));
                    }

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      if (uaRegex.matcher(c.element().getValue()).matches()) {
                        c.output(c.element());
                      }
                    }
                  }))
          .apply(GroupByKey.<String, String>create())
          .apply(
              "user agent blocklist analysis",
              ParDo.of(
                      new DoFn<KV<String, Iterable<String>>, Alert>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c, BoundedWindow w) {
                          Map<String, Boolean> nv = c.sideInput(natView);

                          String saddr = c.element().getKey();
                          // Iterable user agent list not currently used here, could probably be
                          // included in the alert metadata though.

                          Boolean isNat = nv.get(saddr);
                          if (isNat != null && isNat) {
                            log.info(
                                "{}: detectnat: skipping result emission for {}",
                                w.toString(),
                                saddr);
                            metrics.natDetected();
                            return;
                          }

                          Alert a = new Alert();
                          a.setSummary(
                              String.format(
                                  "%s httprequest useragent_blocklist %s",
                                  monitoredResource, saddr));
                          a.setCategory("httprequest");
                          a.setSubcategory("useragent_blocklist");
                          a.addMetadata(AlertMeta.Key.SOURCEADDRESS, saddr);

                          try {
                            if (enableIprepdDatastoreExemptions) {
                              IprepdIO.addMetadataIfIpIsExempt(
                                  saddr, a, iprepdDatastoreExemptionsProject);
                            }
                          } catch (IOException exc) {
                            log.error("error checking iprepd exemptions: {}", exc.getMessage());
                            return;
                          }

                          a.setNotifyMergeKey(
                              String.format("%s useragent_blocklist", monitoredResource));
                          a.addMetadata(
                              AlertMeta.Key.WINDOW_TIMESTAMP,
                              (new DateTime(w.maxTimestamp())).toString());

                          if (!a.hasCorrectFields()) {
                            throw new IllegalArgumentException(
                                "alert has invalid field configuration");
                          }
                          c.output(a);
                        }
                      })
                  .withSideInputs(natView));
    }
  }

  /**
   * Transform for detection of a single source making excessive requests of a specific endpoint
   * path solely.
   *
   * <p>Generates alerts where the request profile violates path thresholds specified in the
   * endpointAbusePath pipeline option configuration.
   */
  public static class EndpointAbuseAnalysis
      extends PTransform<PCollection<KV<String, ArrayList<String>>>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private Logger log;

    private final EndpointAbuseEndpointInfo[] endpoints;
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreExemptions;
    private final Boolean varianceSupportingOnly;
    private final String[] customVarianceSubstrings;
    private final String iprepdDatastoreExemptionsProject;
    private final Integer suppressRecovery;
    private final Long sessionGapDurationMinutes;
    private final Long alertSuppressionDurationSeconds;

    /** Internal class for configured endpoints in EPA */
    public static class EndpointAbuseEndpointInfo implements Serializable {
      private static final long serialVersionUID = 1L;

      /** Request method */
      public String method;
      /** Request path */
      public String path;
      /** Threshold */
      public Integer threshold;
    }

    /** Internal class for endpoint abuse state */
    public static class EndpointAbuseState implements Serializable {
      private static final long serialVersionUID = 1L;

      /** Remote address */
      public String remoteAddress;
      /** Request count */
      public Integer count;
      /** Timestamp */
      public Instant timestamp;
    }

    /**
     * Static initializer for {@link EndpointAbuseAnalysis}
     *
     * @param toggles {@link HTTPRequestToggles}
     * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
     * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
     */
    public EndpointAbuseAnalysis(
        HTTPRequestToggles toggles,
        Boolean enableIprepdDatastoreExemptions,
        String iprepdDatastoreExemptionsProject) {
      log = LoggerFactory.getLogger(EndpointAbuseAnalysis.class);

      monitoredResource = toggles.getMonitoredResource();
      this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
      this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
      varianceSupportingOnly = toggles.getEndpointAbuseExtendedVariance();
      suppressRecovery = toggles.getEndpointAbuseSuppressRecovery();
      customVarianceSubstrings = toggles.getEndpointAbuseCustomVarianceSubstrings();
      sessionGapDurationMinutes = toggles.getSessionGapDurationMinutes();
      alertSuppressionDurationSeconds = toggles.getAlertSuppressionDurationSeconds();

      String[] cfgEndpoints = toggles.getEndpointAbusePath();
      endpoints = new EndpointAbuseEndpointInfo[cfgEndpoints.length];
      for (int i = 0; i < cfgEndpoints.length; i++) {
        String[] parts = cfgEndpoints[i].split(":");
        if (parts.length != 3) {
          throw new IllegalArgumentException(
              "invalid format for abuse endpoint path, must be <int>:<method>:<path>");
        }
        EndpointAbuseEndpointInfo ninfo = new EndpointAbuseEndpointInfo();
        ninfo.threshold = Integer.parseInt(parts[0]);
        ninfo.method = parts[1];
        ninfo.path = parts[2];
        endpoints[i] = ninfo;
      }
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      String buf = null;
      for (int i = 0; i < endpoints.length; i++) {
        String x =
            String.format(
                "%d %s requests for %s.",
                endpoints[i].threshold, endpoints[i].method, endpoints[i].path);
        if (buf == null) {
          buf = x;
        } else {
          buf += " " + x;
        }
      }
      return String.format(
          "Clients are sessionized by address, where a session ends after "
              + "%d minutes of inactivity. An alert is generated if a client is observed "
              + "making repeated requests to configured endpoints without requesting other forms "
              + "of content from the site. %s",
          sessionGapDurationMinutes, buf);
    }

    @Override
    public PCollection<Alert> expand(PCollection<KV<String, ArrayList<String>>> input) {
      return input
          .apply(GroupByKey.<String, ArrayList<String>>create())
          .apply(
              "analyze per-client",
              ParDo.of(
                  new DoFn<KV<String, Iterable<ArrayList<String>>>, KV<String, Alert>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c, BoundedWindow w) {
                      String remoteAddress = c.element().getKey();
                      Iterable<ArrayList<String>> paths = c.element().getValue();
                      int[] endCounter = new int[endpoints.length];
                      String userAgent = null;
                      boolean basicVariance = false;
                      boolean extendedVariance = false;

                      // Used to track the latest applicable EPA request, so we can use it as the
                      // alert timestamp if we need to generate an alert.
                      Instant latestEpaRequest = null;

                      // Count the number of requests in-window for this source that map to
                      // monitored endpoints. Set a basic variance flag if we see a request
                      // that was made to something that is not monitored.
                      for (ArrayList<String> i : paths) {
                        Integer abIdx = indexEndpoint(i.get(1), i.get(0));
                        if (abIdx == null) {
                          if (customVarianceSubstrings != null) {
                            for (String s : customVarianceSubstrings) {
                              if (i.get(4).contains(s)) {
                                basicVariance = true;
                                extendedVariance = true;
                              }
                            }
                          }
                          basicVariance = true;
                          if (considerSupporting(i.get(1))) {
                            extendedVariance = true;
                          }
                          continue;
                        }
                        Instant t = Instant.parse(i.get(3));
                        if (latestEpaRequest == null) {
                          latestEpaRequest = t;
                        } else if (t.getMillis() > latestEpaRequest.getMillis()) {
                          latestEpaRequest = t;
                        }
                        // XXX Just pick up the user agent here; with agent variance this could
                        // result in a different agent being included in the alert than the one
                        // that was actually associated with the threshold violation, and should
                        // be fixed.
                        userAgent = i.get(2);
                        endCounter[abIdx]++;
                      }

                      // If extended object variance is enabled, only consider variance if this
                      // flag has been set. Otherwise we by default consider basic variance to be
                      // enough.
                      if (varianceSupportingOnly) {
                        if (extendedVariance) {
                          return;
                        }
                      } else {
                        if (basicVariance) {
                          return;
                        }
                      }

                      // If we get here, there was not enough variance present, identify if any
                      // monitored endpoints have exceeded the threshold and use the one with
                      // the highest request count
                      Integer abmaxIndex = null;
                      int count = -1;
                      for (int i = 0; i < endpoints.length; i++) {
                        if (endpoints[i].threshold <= endCounter[i]) {
                          if (abmaxIndex == null) {
                            abmaxIndex = i;
                            count = endCounter[i];
                          } else {
                            if (count < endCounter[i]) {
                              abmaxIndex = i;
                              count = endCounter[i];
                            }
                          }
                        }
                      }

                      if (abmaxIndex == null) {
                        // No requests exceeded threshold
                        return;
                      }

                      log.info("{}: emitting alert for {} {}", w.toString(), remoteAddress, count);

                      String compareMethod = endpoints[abmaxIndex].method;
                      String comparePath = endpoints[abmaxIndex].path;

                      Alert a = new Alert();
                      a.setTimestamp(latestEpaRequest.toDateTime());
                      a.setSummary(
                          String.format(
                              "%s httprequest endpoint_abuse %s %s %s %d",
                              monitoredResource, remoteAddress, compareMethod, comparePath, count));
                      a.setCategory("httprequest");
                      a.setSubcategory("endpoint_abuse");
                      a.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);

                      try {
                        if (enableIprepdDatastoreExemptions) {
                          IprepdIO.addMetadataIfIpIsExempt(
                              remoteAddress, a, iprepdDatastoreExemptionsProject);
                        }
                      } catch (IOException exc) {
                        log.error("error checking iprepd exemptions: {}", exc.getMessage());
                        return;
                      }

                      if (suppressRecovery != null) {
                        IprepdIO.addMetadataSuppressRecovery(suppressRecovery, a);
                      }

                      a.addMetadata(AlertMeta.Key.ENDPOINT, comparePath);
                      a.addMetadata(AlertMeta.Key.METHOD, compareMethod);
                      a.addMetadata(AlertMeta.Key.COUNT, Integer.toString(count));
                      a.addMetadata(AlertMeta.Key.USERAGENT, userAgent);
                      a.setNotifyMergeKey(String.format("%s endpoint_abuse", monitoredResource));
                      a.addMetadata(
                          AlertMeta.Key.WINDOW_TIMESTAMP,
                          (new DateTime(w.maxTimestamp())).toString());
                      if (!a.hasCorrectFields()) {
                        throw new IllegalArgumentException("alert has invalid field configuration");
                      }
                      c.output(KV.of(remoteAddress, a));
                    }
                  }))
          // Rewindow into global windows so we can use state in the next step
          //
          // Ideally we would apply state in the previous step, but this is not currently
          // supported by DataflowRunner.
          //
          // See also https://issues.apache.org/jira/browse/BEAM-2507
          .apply("endpoint abuse analysis global", new GlobalTriggers<KV<String, Alert>>(5))
          .apply(ParDo.of(new AlertSuppressorCount(alertSuppressionDurationSeconds)));
    }

    private Boolean considerSupporting(String path) {
      if ((path.endsWith(".css"))
          || (path.endsWith(".js"))
          || (path.endsWith(".gif"))
          || (path.endsWith(".jpg"))
          || (path.endsWith(".ico"))
          || (path.endsWith(".svg"))
          || (path.endsWith(".png"))) {
        return true;
      }
      return false;
    }

    private Integer indexEndpoint(String path, String method) {
      for (int i = 0; i < endpoints.length; i++) {
        if ((endpoints[i].method.equals(method)) && (endpoints[i].path.equals(path))) {
          return i;
        }
      }
      return null;
    }
  }

  /**
   * Composite transform that conducts threshold analysis using the configured threshold modifier
   */
  public static class ThresholdAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final Double thresholdModifier;
    private final Double requiredMinimumAverage;
    private final Long requiredMinimumClients;
    private final Double clampThresholdMaximum;
    private final Long requiredMinimumRequestsPerClient;
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreExemptions;
    private final String iprepdDatastoreExemptionsProject;
    private PCollectionView<Map<String, Boolean>> natView = null;

    private final HeuristicMetrics metrics;
    private Logger log;

    /**
     * Static initializer for {@link ThresholdAnalysis}.
     *
     * @param toggles {@link HTTPRequestToggles}
     * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
     * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
     * @param natView Use {@link DetectNat} view, or null to disable
     */
    public ThresholdAnalysis(
        HTTPRequestToggles toggles,
        Boolean enableIprepdDatastoreExemptions,
        String iprepdDatastoreExemptionsProject,
        PCollectionView<Map<String, Boolean>> natView) {
      this.thresholdModifier = toggles.getAnalysisThresholdModifier();
      this.requiredMinimumAverage = toggles.getRequiredMinimumAverage();
      this.requiredMinimumClients = toggles.getRequiredMinimumClients();
      this.requiredMinimumRequestsPerClient = toggles.getRequiredMinimumRequestsPerClient();
      this.clampThresholdMaximum = toggles.getClampThresholdMaximum();
      this.monitoredResource = toggles.getMonitoredResource();
      this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
      this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
      this.natView = natView;
      this.metrics = new HeuristicMetrics(ThresholdAnalysis.class.getName());
      log = LoggerFactory.getLogger(ThresholdAnalysis.class);
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return String.format(
          "Alert if a single source address makes more than %.2f times the calculated"
              + " mean request rate for all clients within a 1 minute window.",
          thresholdModifier);
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
                          Normalized n = c.element().getNormalized();
                          if (n.getSourceAddress() == null) {
                            return;
                          }
                          c.output(n.getSourceAddress());
                        }
                      }))
              .apply(Count.<String>perElement());

      // For each client, extract the request count
      PCollection<Long> counts = clientCounts.apply("extract counts", Values.<Long>create());

      // Obtain statistics on the client count population for use as a side input
      final PCollectionView<Stats.StatsOutput> wStats = Stats.getView(counts);

      return clientCounts
          .apply(
              "filter insignificant",
              ParDo.of(
                  new DoFn<KV<String, Long>, KV<String, Long>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      if (c.element().getValue() >= requiredMinimumRequestsPerClient) {
                        c.output(c.element());
                      }
                    }
                  }))
          .apply(
              "apply thresholds",
              ParDo.of(
                      new DoFn<KV<String, Long>, Alert>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c, BoundedWindow w) {
                          Stats.StatsOutput sOutput = c.sideInput(wStats);
                          Long uc = sOutput.getTotalElements();
                          Map<String, Boolean> nv = c.sideInput(natView);

                          Double cMean = sOutput.getMean();

                          if (uc < requiredMinimumClients) {
                            return;
                          }

                          if (cMean < requiredMinimumAverage) {
                            return;
                          }

                          if ((clampThresholdMaximum != null) && (cMean > clampThresholdMaximum)) {
                            cMean = clampThresholdMaximum;
                          }

                          if (c.element().getValue() >= (cMean * thresholdModifier)) {
                            Boolean isNat = nv.get(c.element().getKey());
                            if (isNat != null && isNat) {
                              log.info(
                                  "{}: detectnat: skipping result emission for {}",
                                  w.toString(),
                                  c.element().getKey());
                              metrics.natDetected();
                              return;
                            }
                            log.info(
                                "{}: emitting alert for {}", w.toString(), c.element().getKey());
                            Alert a = new Alert();
                            a.setSummary(
                                String.format(
                                    "%s httprequest threshold_analysis %s %d",
                                    monitoredResource,
                                    c.element().getKey(),
                                    c.element().getValue()));
                            a.setCategory("httprequest");
                            a.setSubcategory("threshold_analysis");
                            a.addMetadata(AlertMeta.Key.SOURCEADDRESS, c.element().getKey());

                            try {
                              if (enableIprepdDatastoreExemptions) {
                                IprepdIO.addMetadataIfIpIsExempt(
                                    c.element().getKey(), a, iprepdDatastoreExemptionsProject);
                              }
                            } catch (IOException exc) {
                              log.error("error checking iprepd exemptions: {}", exc.getMessage());
                              return;
                            }

                            a.addMetadata(AlertMeta.Key.MEAN, sOutput.getMean().toString());
                            a.addMetadata(AlertMeta.Key.COUNT, c.element().getValue().toString());
                            a.addMetadata(
                                AlertMeta.Key.THRESHOLD_MODIFIER, thresholdModifier.toString());
                            a.setNotifyMergeKey(
                                String.format("%s threshold_analysis", monitoredResource));
                            a.addMetadata(
                                AlertMeta.Key.WINDOW_TIMESTAMP,
                                (new DateTime(w.maxTimestamp())).toString());
                            if (!a.hasCorrectFields()) {
                              throw new IllegalArgumentException(
                                  "alert has invalid field configuration");
                            }
                            c.output(a);
                          }
                        }
                      })
                  .withSideInputs(wStats, natView));
    }
  }

  /**
   * Transform for detection of a single source making a sequence of requests at a speed faster than
   * what we expect from a normal user.
   *
   * <p>Generates alerts where the request profile violates path thresholds specified in the
   * endpointAbusePath pipeline option configuration.
   */
  public static class EndpointSequenceAbuse
      extends PTransform<PCollection<Event>, PCollection<Alert>> implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private Logger log;

    private final EndpointSequenceAbuseTimingInfo[] endpointPatterns;
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreExemptions;
    private final String iprepdDatastoreExemptionsProject;
    private final Integer suppressRecovery;
    private PCollectionView<Map<String, Boolean>> natView = null;
    private final HeuristicMetrics metrics;

    /** Internal class for configured endpoints in EPA */
    public static class EndpointSequenceAbuseTimingInfo implements Serializable {
      private static final long serialVersionUID = 1L;

      public Integer threshold;

      public String firstMethod;
      public String firstPath;

      public Integer deltaMs;

      public String secondMethod;
      public String secondPath;

      /**
       * Convert configuration to String
       *
       * @return Class parameters as a string
       */
      public String toString() {
        return String.format(
            "%d:%s:%s:%d:%s:%s",
            threshold, firstMethod, firstPath, deltaMs, secondMethod, secondPath);
      }
    }

    /**
     * Static initializer for {@link EndpointAbuseAnalysis}
     *
     * @param toggles {@link HTTPRequestToggles}
     * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
     * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
     * @param natView Use {@link DetectNat} view, or null to disable
     */
    public EndpointSequenceAbuse(
        HTTPRequestToggles toggles,
        Boolean enableIprepdDatastoreExemptions,
        String iprepdDatastoreExemptionsProject,
        PCollectionView<Map<String, Boolean>> natView) {
      log = LoggerFactory.getLogger(EndpointSequenceAbuse.class);
      monitoredResource = toggles.getMonitoredResource();
      this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
      this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
      suppressRecovery = toggles.getEndpointSequenceAbuseSuppressRecovery();
      this.natView = natView;
      metrics = new HeuristicMetrics(EndpointSequenceAbuse.class.getName());

      String[] cfgEndpoints = toggles.getEndpointSequenceAbusePatterns();
      endpointPatterns = new EndpointSequenceAbuseTimingInfo[cfgEndpoints.length];
      for (int i = 0; i < cfgEndpoints.length; i++) {
        String[] parts = cfgEndpoints[i].split(":");
        if (parts.length != 6) {
          throw new IllegalArgumentException(
              "invalid format for abuse endpoint timing, must be <int>:<method>:<path>:<int>:<method>:<path>");
        }
        EndpointSequenceAbuseTimingInfo ninfo = new EndpointSequenceAbuseTimingInfo();
        ninfo.threshold = Integer.parseInt(parts[0]);
        ninfo.firstMethod = parts[1];
        ninfo.firstPath = parts[2];
        ninfo.deltaMs = Integer.parseInt(parts[3]);
        ninfo.secondMethod = parts[4];
        ninfo.secondPath = parts[5];
        endpointPatterns[i] = ninfo;
      }
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      String buf = null;
      for (int i = 0; i < endpointPatterns.length; i++) {
        String x =
            String.format(
                "%d %s %s requests within %d ms of last %s %s request.",
                endpointPatterns[i].threshold,
                endpointPatterns[i].secondMethod,
                endpointPatterns[i].secondPath,
                endpointPatterns[i].deltaMs,
                endpointPatterns[i].firstMethod,
                endpointPatterns[i].firstPath);
        if (buf == null) {
          buf = x;
        } else {
          buf += " " + x;
        }
      }
      return String.format(
          "An alert is generated when a client (identified by ip) makes requests for a sequence of endpoints within a configurable delta thought to be atypical of a normal user. %s",
          buf);
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      if (natView == null) {
        // If natView was not set then we just create an empty view for use as the side input
        natView = DetectNat.getEmptyView(input.getPipeline());
      }
      return input
          .apply(
              "filter events and key by ip",
              ParDo.of(
                  new DoFn<Event, KV<String, Event>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c, BoundedWindow w) {
                      Event event = c.element();
                      Normalized n = event.getNormalized();
                      String sourceAddress = n.getSourceAddress();
                      String method = n.getRequestMethod();
                      String path = n.getUrlRequestPath();
                      if (sourceAddress == null || method == null || path == null) {
                        return;
                      }
                      // only output events if they belong to one of our sequences
                      if (belongsToSequence(method, path)) {
                        c.output(KV.of(sourceAddress, event));
                      }
                    }
                  }))
          .apply(GroupByKey.<String, Event>create())
          .apply(
              "analyze per-client",
              ParDo.of(
                      new DoFn<KV<String, Iterable<Event>>, Alert>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c, BoundedWindow w) {
                          String remoteAddress = c.element().getKey();
                          Iterable<Event> events = c.element().getValue();

                          // sort events by timestamp
                          List<Event> eventList =
                              StreamSupport.stream(events.spliterator(), false)
                                  .sorted(
                                      (e1, e2) -> e1.getTimestamp().compareTo(e2.getTimestamp()))
                                  .collect(Collectors.toList());

                          int[] violationsCounter = new int[endpointPatterns.length];
                          Instant[] lastViolationTimestamp = new Instant[endpointPatterns.length];
                          String[] lastViolationUserAgent = new String[endpointPatterns.length];

                          // used to track last time we saw the first part of each
                          // request sequence used for timing analysis
                          Instant[] lastFirstRequest = new Instant[endpointPatterns.length];

                          // for each path
                          for (Event event : eventList) {
                            Normalized n = event.getNormalized();

                            // check if its a first item in an endpoint sequence
                            ArrayList<Integer> indices =
                                findFirstHalfPatternMatches(
                                    n.getRequestMethod(), n.getUrlRequestPath());

                            // for any sequence its a part of update the latest timestamp for it
                            for (Integer m : indices) {
                              lastFirstRequest[m] = Instant.parse(event.getTimestamp().toString());
                            }

                            // check if its a second item in an endpoint sequence
                            ArrayList<Integer> secondIndices =
                                findSecondHalfPatternMatches(
                                    n.getRequestMethod(), n.getUrlRequestPath());

                            // for any sequence its the second part of, check the delta and increase
                            // count if it is
                            for (Integer m : secondIndices) {
                              Instant ts = Instant.parse(event.getTimestamp().toString());
                              if (lastFirstRequest[m] != null) {
                                if (ts.isBefore(
                                    lastFirstRequest[m].plus(endpointPatterns[m].deltaMs))) {
                                  lastViolationUserAgent[m] =
                                      n.getUserAgent() == null ? "" : n.getUserAgent();
                                  lastViolationTimestamp[m] = ts;
                                  violationsCounter[m]++;
                                }
                              }
                            }
                          }

                          // identify if any monitored endpoints have
                          // exceeded the threshold and use the one with
                          // the highest count
                          Integer abmaxIndex = null;
                          int count = -1;
                          for (int i = 0; i < endpointPatterns.length; i++) {
                            if (endpointPatterns[i].threshold <= violationsCounter[i]) {
                              if (abmaxIndex == null) {
                                abmaxIndex = i;
                                count = violationsCounter[i];
                              } else {
                                if (count < violationsCounter[i]) {
                                  abmaxIndex = i;
                                  count = violationsCounter[i];
                                }
                              }
                            }
                          }

                          if (abmaxIndex == null) {
                            // No requests exceeded threshold
                            return;
                          }

                          Map<String, Boolean> nv = c.sideInput(natView);
                          Boolean isNat = nv.get(remoteAddress);
                          if (isNat != null && isNat) {
                            log.info(
                                "{}: detectnat: skipping result emission for {}",
                                w.toString(),
                                remoteAddress);
                            metrics.natDetected();
                            return;
                          }

                          log.info(
                              "{}: emitting alert for {} {}", w.toString(), remoteAddress, count);

                          String compareFirstMethod = endpointPatterns[abmaxIndex].firstMethod;
                          String compareFirstPath = endpointPatterns[abmaxIndex].firstPath;

                          Integer compareDelta = endpointPatterns[abmaxIndex].deltaMs;

                          String compareSecondMethod = endpointPatterns[abmaxIndex].secondMethod;
                          String compareSecondPath = endpointPatterns[abmaxIndex].secondPath;

                          Alert a = new Alert();
                          a.setTimestamp(lastViolationTimestamp[abmaxIndex].toDateTime());
                          a.setSummary(
                              String.format(
                                  "%s httprequest endpoint_sequence_abuse %s %s:%s:%d:%s:%s %d",
                                  monitoredResource,
                                  remoteAddress,
                                  compareFirstMethod,
                                  compareFirstPath,
                                  compareDelta,
                                  compareSecondMethod,
                                  compareSecondPath,
                                  count));
                          a.setCategory("httprequest");
                          a.setSubcategory("endpoint_sequence_abuse");
                          a.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);

                          try {
                            if (enableIprepdDatastoreExemptions) {
                              IprepdIO.addMetadataIfIpIsExempt(
                                  remoteAddress, a, iprepdDatastoreExemptionsProject);
                            }
                          } catch (IOException exc) {
                            log.error("error checking iprepd exemptions: {}", exc.getMessage());
                            return;
                          }

                          if (suppressRecovery != null) {
                            IprepdIO.addMetadataSuppressRecovery(suppressRecovery, a);
                          }

                          a.addMetadata(
                              AlertMeta.Key.ENDPOINT_PATTERN,
                              endpointPatterns[abmaxIndex].toString());
                          a.addMetadata(AlertMeta.Key.COUNT, Integer.toString(count));
                          a.addMetadata(
                              AlertMeta.Key.USERAGENT, lastViolationUserAgent[abmaxIndex]);
                          a.setNotifyMergeKey(
                              String.format("%s endpoint_sequence_abuse", monitoredResource));
                          a.addMetadata(
                              AlertMeta.Key.WINDOW_TIMESTAMP,
                              (new DateTime(w.maxTimestamp())).toString());
                          if (!a.hasCorrectFields()) {
                            throw new IllegalArgumentException(
                                "alert has invalid field configuration");
                          }
                          c.output(a);
                        }
                      })
                  .withSideInputs(natView));
    }

    /**
     * Returns the indices of the endpoint sequences that the given method/path match the first part
     * of the pattern
     */
    private ArrayList<Integer> findFirstHalfPatternMatches(String method, String path) {
      ArrayList<Integer> indices = new ArrayList<Integer>();
      for (int i = 0; i < endpointPatterns.length; i++) {
        if ((endpointPatterns[i].firstMethod.equals(method))
            && (endpointPatterns[i].firstPath.equals(path))) {
          indices.add(i);
        }
      }
      return indices;
    }

    /**
     * Returns the indices of the endpoint sequences that the given method/path match the second
     * part of the pattern
     */
    private ArrayList<Integer> findSecondHalfPatternMatches(String method, String path) {
      ArrayList<Integer> indices = new ArrayList<Integer>();
      for (int i = 0; i < endpointPatterns.length; i++) {
        if ((endpointPatterns[i].secondMethod.equals(method))
            && (endpointPatterns[i].secondPath.equals(path))) {
          indices.add(i);
        }
      }
      return indices;
    }

    /**
     * Returns true if the method/path combination is part of any sequence (regardless of position)
     */
    private Boolean belongsToSequence(String method, String path) {
      return !(findFirstHalfPatternMatches(method, path).isEmpty()
          && findSecondHalfPatternMatches(method, path).isEmpty());
    }
  }

  /**
   * Transform for detection of a single source generating errors at a given path pattern. The path
   * is specified using a regex and an alert is generated if there are more than the threshold
   * amount of requests matching the path with a status in the 400's.
   *
   * <p>Generates alerts where the request profile violates path thresholds specified in the
   * perEndpointErrorRate pipeline option configuration.
   */
  public static class PerEndpointErrorRateAnalysis
      extends PTransform<PCollection<KV<String, ArrayList<String>>>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private Logger log;
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreExemptions;
    private final String iprepdDatastoreExemptionsProject;
    private final EndpointErrorInfo[] endpointInfo;
    private final Integer suppressRecovery;
    private final Long sessionGapDurationMinutes;
    private final Long alertSuppressionDurationSeconds;

    /**
     * Initializer for {@link PerEndpointErrorRateAnalysis}
     *
     * @param toggles {@link HTTPRequestToggles}
     * @param enableIprepdDatastoreExemptions True to enable datastore exemptions
     * @param iprepdDatastoreExemptionsProject Project to look for datastore entities in
     */
    public PerEndpointErrorRateAnalysis(
        HTTPRequestToggles toggles,
        Boolean enableIprepdDatastoreExemptions,
        String iprepdDatastoreExemptionsProject) {
      log = LoggerFactory.getLogger(PerEndpointErrorRateAnalysis.class);

      this.monitoredResource = toggles.getMonitoredResource();
      this.enableIprepdDatastoreExemptions = enableIprepdDatastoreExemptions;
      this.iprepdDatastoreExemptionsProject = iprepdDatastoreExemptionsProject;
      this.suppressRecovery = toggles.getPerEndpointErrorRateSuppressRecovery();
      this.sessionGapDurationMinutes = toggles.getErrorSessionGapDurationMinutes();
      this.alertSuppressionDurationSeconds =
          toggles.getPerEndpointErrorRateAlertSuppressionDurationSeconds();

      String[] cfgEndpoints = toggles.getPerEndpointErrorRatePaths();

      this.endpointInfo = new EndpointErrorInfo[cfgEndpoints.length];

      for (int i = 0; i < cfgEndpoints.length; i++) {
        String[] parts = cfgEndpoints[i].split(":");
        if (parts.length != 3) {
          throw new IllegalArgumentException(
              "invalid format for per endpoint error rate analysis, must be <int>:<method>:<path>");
        }
        EndpointErrorInfo ninfo = new EndpointErrorInfo();
        ninfo.threshold = Integer.parseInt(parts[0]);
        ninfo.method = parts[1];
        ninfo.path = Pattern.compile(parts[2]);

        endpointInfo[i] = ninfo;
      }
    }

    /** Internal class for configured endpoints in PEERA */
    public static class EndpointErrorInfo implements Serializable {
      private static final long serialVersionUID = 1L;

      /** Request method */
      public String method;

      /** Path (pattern) */
      public Pattern path;

      /** Threshold */
      public Integer threshold;

      /** Interval */
      public Long interval;

      /** Returns true if an event matches the endpoint for both method and path */
      boolean matchesEvent(String eventMethod, String eventPath) {
        return method.equals(eventMethod) && path.matcher(eventPath).matches();
      }
    }

    /** Internal class to keep track of current state for a given endpoint rule for this key */
    public static class EndpointErrorState implements Serializable {
      private static final long serialVersionUID = 1L;
      int errorCounter;
      Instant mostRecentError;
      String userAgent;

      /**
       * Increments the counter and if this is the most recent event seen update the timestamp and
       * use this event's useragent for any alerts generated
       */
      void update(Instant timestamp, String userAgent) {
        errorCounter++;
        if (mostRecentError == null || mostRecentError.isBefore(timestamp)) {
          mostRecentError = timestamp;
          this.userAgent = userAgent;
        }
      }
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      String buf = null;
      for (int i = 0; i < endpointInfo.length; i++) {
        String x =
            String.format(
                "%d errors to endpoints matching %s %s.",
                endpointInfo[i].threshold, endpointInfo[i].method, endpointInfo[i].path);
        if (buf == null) {
          buf = x;
        } else {
          buf += " " + x;
        }
      }
      return String.format(
          "Clients are sessionized by address, where a session ends after "
              + "%d minutes of inactivity. An alert is generated if a client is observed "
              + "making repeated requests to configured endpoints that result in higher "
              + "amount of errors. %s",
          sessionGapDurationMinutes, buf);
    }

    @Override
    public PCollection<Alert> expand(PCollection<KV<String, ArrayList<String>>> input) {
      return input
          .apply(GroupByKey.<String, ArrayList<String>>create())
          .apply(
              "analyze per-client",
              ParDo.of(
                  new DoFn<KV<String, Iterable<ArrayList<String>>>, KV<String, Alert>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c, BoundedWindow w) {
                      String remoteAddress = c.element().getKey();
                      Iterable<ArrayList<String>> errors = c.element().getValue();
                      EndpointErrorState[] state = new EndpointErrorState[endpointInfo.length];
                      Arrays.setAll(state, i -> new EndpointErrorState());

                      for (ArrayList<String> e : errors) {
                        String method = e.get(0);
                        String path = e.get(1);
                        for (int i = 0; i < endpointInfo.length; i++) {
                          if (endpointInfo[i].matchesEvent(method, path)) {
                            Instant ts = Instant.parse(e.get(3));
                            String userAgent = e.get(2);
                            state[i].update(ts, userAgent);
                          }
                        }
                      }

                      // find the endpoint with the highest count and use that to
                      // generate alert
                      Integer max = null;
                      int count = -1;
                      for (int i = 0; i < endpointInfo.length; i++) {
                        if (endpointInfo[i].threshold <= state[i].errorCounter) {
                          if (max == null) {
                            max = i;
                            count = state[i].errorCounter;
                          } else {
                            if (count < state[i].errorCounter) {
                              max = i;
                              count = state[i].errorCounter;
                            }
                          }
                        }
                      }

                      if (max == null) {
                        return;
                      }

                      Alert a = new Alert();
                      a.setTimestamp(state[max].mostRecentError.toDateTime());
                      a.setSummary(
                          String.format(
                              "%s httprequest per_endpoint_error_rate %s %s %s %d",
                              monitoredResource,
                              remoteAddress,
                              endpointInfo[max].method,
                              endpointInfo[max].path.pattern(),
                              state[max].errorCounter));
                      a.setCategory("httprequest");
                      a.setSubcategory("per_endpoint_error_rate");
                      a.addMetadata(AlertMeta.Key.SOURCEADDRESS, remoteAddress);

                      if (enableIprepdDatastoreExemptions) {
                        try {
                          IprepdIO.addMetadataIfIpIsExempt(
                              remoteAddress, a, iprepdDatastoreExemptionsProject);
                        } catch (IOException exc) {
                          log.error("error checking iprepd exemptions: {}", exc.getMessage());
                          return;
                        }
                      }
                      if (suppressRecovery != null) {
                        IprepdIO.addMetadataSuppressRecovery(suppressRecovery, a);
                      }
                      a.addMetadata(AlertMeta.Key.COUNT, String.valueOf(state[max].errorCounter));
                      a.addMetadata(
                          AlertMeta.Key.ENDPOINT_PATTERN, endpointInfo[max].path.toString());
                      a.addMetadata(
                          AlertMeta.Key.ERROR_THRESHOLD,
                          String.valueOf(endpointInfo[max].threshold));
                      a.setNotifyMergeKey(
                          String.format("%s per_endpoint_error_rate", monitoredResource));
                      a.addMetadata(
                          AlertMeta.Key.WINDOW_TIMESTAMP,
                          (new DateTime(w.maxTimestamp())).toString());
                      if (!a.hasCorrectFields()) {
                        throw new IllegalArgumentException("alert has invalid field configuration");
                      }
                      c.output(KV.of(remoteAddress, a));
                    }
                  }))
          .apply("per endpoint error analysis global", new GlobalTriggers<KV<String, Alert>>(5))
          .apply(ParDo.of(new AlertSuppressorCount(alertSuppressionDurationSeconds)));
    }
  }

  /** Function to be used with filter transform in order to include only client errors */
  public static class Has4xxRequestStatus implements SerializableFunction<Event, Boolean> {
    private static final long serialVersionUID = 1L;

    @Override
    public Boolean apply(Event event) {
      Normalized n = event.getNormalized();
      if (n.getRequestStatus() != null
          && n.getRequestStatus() >= 400
          && n.getRequestStatus() < 500) {
        return true;
      } else return false;
    }
  }

  private static class HTTPRequestAnalysis
      extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final transient HTTPRequestToggles toggles;
    private final Boolean enableIprepdDatastoreExemptions;
    private final String iprepdDatastoreExemptionsProject;
    private final String monitoredResource;
    private final String maxmindCityDbPath;
    private final String maxmindIspDbPath;
    private final String initialNatListPath;

    /**
     * Create new HTTPRequestAnalysis
     *
     * @param options Pipeline options
     * @param toggles Element toggles
     */
    public HTTPRequestAnalysis(HTTPRequestOptions options, HTTPRequestToggles toggles) {
      this.toggles = toggles;

      enableIprepdDatastoreExemptions = options.getOutputIprepdEnableDatastoreExemptions();
      iprepdDatastoreExemptionsProject = options.getOutputIprepdDatastoreExemptionsProject();
      monitoredResource = toggles.getMonitoredResource();
      maxmindCityDbPath = options.getMaxmindCityDbPath();
      maxmindIspDbPath = options.getMaxmindIspDbPath();
      initialNatListPath = toggles.getKnownGatewaysPath();
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> events) {
      PCollectionList<Alert> resultsList = PCollectionList.empty(events.getPipeline());

      if (toggles.getEnableThresholdAnalysis()
          || toggles.getEnableErrorRateAnalysis()
          || toggles.getEnableHardLimitAnalysis()
          || toggles.getEnableUserAgentBlocklistAnalysis()
          || toggles.getEnableEndpointSequenceAbuseAnalysis()) {
        PCollection<Event> fwEvents = events.apply("window for fixed", new WindowForFixed());

        PCollectionView<Map<String, Boolean>> natView = null;
        if (toggles.getEnableNatDetection()) {
          natView = DetectNat.getView(fwEvents, initialNatListPath);
        }

        if (toggles.getEnableThresholdAnalysis()) {
          resultsList =
              resultsList.and(
                  fwEvents
                      .apply(
                          "threshold analysis",
                          new ThresholdAnalysis(
                              toggles,
                              enableIprepdDatastoreExemptions,
                              iprepdDatastoreExemptionsProject,
                              natView))
                      .apply("threshold analysis global triggers", new GlobalTriggers<Alert>(5)));
        }

        if (toggles.getEnableHardLimitAnalysis()) {
          resultsList =
              resultsList.and(
                  fwEvents
                      .apply(
                          "hard limit analysis",
                          new HardLimitAnalysis(
                              toggles,
                              enableIprepdDatastoreExemptions,
                              iprepdDatastoreExemptionsProject,
                              natView))
                      .apply("hard limit analysis global triggers", new GlobalTriggers<Alert>(5)));
        }

        if (toggles.getEnableErrorRateAnalysis()) {
          resultsList =
              resultsList.and(
                  fwEvents
                      .apply(
                          "error rate analysis",
                          new ErrorRateAnalysis(
                              toggles,
                              enableIprepdDatastoreExemptions,
                              iprepdDatastoreExemptionsProject))
                      .apply("error rate analysis global triggers", new GlobalTriggers<Alert>(5)));
        }

        if (toggles.getEnableUserAgentBlocklistAnalysis()) {
          resultsList =
              resultsList.and(
                  fwEvents
                      .apply(
                          "ua blocklist analysis",
                          new UserAgentBlocklistAnalysis(
                              toggles,
                              enableIprepdDatastoreExemptions,
                              iprepdDatastoreExemptionsProject,
                              natView))
                      .apply(
                          "ua blocklist analysis global triggers", new GlobalTriggers<Alert>(5)));
        }
        if (toggles.getEnableEndpointSequenceAbuseAnalysis()) {
          resultsList =
              resultsList.and(
                  fwEvents
                      .apply(
                          "endpoint abuse timing analysis",
                          new EndpointSequenceAbuse(
                              toggles,
                              enableIprepdDatastoreExemptions,
                              iprepdDatastoreExemptionsProject,
                              natView))
                      .apply(
                          "endpoint sequence abuse global triggers", new GlobalTriggers<Alert>(5)));
        }
      }
      if (toggles.getEnableEndpointAbuseAnalysis()) {
        resultsList =
            resultsList.and(
                events
                    .apply(
                        "key and window for sessions fire early",
                        new KeyAndWindowForSessionsFireEarly(
                            toggles.getSessionGapDurationMinutes()))
                    .apply(
                        "endpoint abuse analysis",
                        new EndpointAbuseAnalysis(
                            toggles,
                            enableIprepdDatastoreExemptions,
                            iprepdDatastoreExemptionsProject)));
      }
      if (toggles.getEnablePerEndpointErrorRateAnalysis()) {
        resultsList =
            resultsList.and(
                events
                    .apply("filter non 4xx requests", Filter.by(new Has4xxRequestStatus()))
                    .apply(
                        "key and window for sessions fire early",
                        new KeyAndWindowForSessionsFireEarly(
                            toggles.getErrorSessionGapDurationMinutes()))
                    .apply(
                        "per endpoint error rate analysis",
                        new PerEndpointErrorRateAnalysis(
                            toggles,
                            enableIprepdDatastoreExemptions,
                            iprepdDatastoreExemptionsProject)));
      }

      PCollection<Alert> allAlerts =
          resultsList
              .apply("flatten analysis output", Flatten.<Alert>pCollections())
              .apply(
                  "output format",
                  ParDo.of(
                      new AlertFormatter(monitoredResource, maxmindCityDbPath, maxmindIspDbPath)));

      if (toggles.getEnableSourceCorrelator()) {
        // Wire up source correlation
        PCollection<SourceCorrelation.SourceData> sourceData =
            PCollectionList.of(
                    events
                        .apply(new GlobalTriggers<Event>(5))
                        .apply(ParDo.of(new SourceCorrelation.EventSourceExtractor())))
                .and(allAlerts.apply(ParDo.of(new SourceCorrelation.AlertSourceExtractor())))
                .apply("flatten source data", Flatten.<SourceCorrelation.SourceData>pCollections());

        allAlerts =
            PCollectionList.of(allAlerts)
                .and(sourceData.apply(new SourceCorrelation.SourceCorrelator(toggles)))
                .apply("flatten with source correlation", Flatten.<Alert>pCollections());
      }

      return allAlerts;
    }
  }

  /** Runtime options for {@link HTTPRequest} pipeline. */
  public interface HTTPRequestOptions extends PipelineOptions, IOOptions {
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

    @Description("Enable endpoint sequence abuse analysis")
    @Default.Boolean(false)
    Boolean getEnableEndpointSequenceAbuseAnalysis();

    void setEnableEndpointSequenceAbuseAnalysis(Boolean value);

    @Description("Enable hard limit analysis")
    @Default.Boolean(false)
    Boolean getEnableHardLimitAnalysis();

    void setEnableHardLimitAnalysis(Boolean value);

    @Description("Enable user agent blocklist analysis")
    @Default.Boolean(false)
    Boolean getEnableUserAgentBlocklistAnalysis();

    void setEnableUserAgentBlocklistAnalysis(Boolean value);

    @Description("Enable per endpoint error rate analysis")
    @Default.Boolean(false)
    Boolean getEnablePerEndpointErrorRateAnalysis();

    void setEnablePerEndpointErrorRateAnalysis(Boolean value);

    @Description("Hard limit request count per window per client")
    @Default.Long(100L)
    Long getHardLimitRequestCount();

    void setHardLimitRequestCount(Long value);

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

    @Description("Required minimum number of requests for threshold analysis")
    @Default.Long(20L)
    Long getRequiredMinimumRequestsPerClient();

    void setRequiredMinimumRequestsPerClient(Long value);

    @Description("Maximum permitted client error rate per window")
    @Default.Long(30L)
    Long getMaxClientErrorRate();

    void setMaxClientErrorRate(Long value);

    @Description("Enable NAT detection for threshold analysis")
    @Default.Boolean(false)
    Boolean getNatDetection();

    void setNatDetection(Boolean value);

    @Description("Path to load initial gateway list for nat detection; resource path, gcs path")
    String getKnownGatewaysPath();

    void setKnownGatewaysPath(String value);

    @Description(
        "Path to load user agent blocklist from for UA blocklist analysis; resource path, gcs path")
    String getUserAgentBlocklistPath();

    void setUserAgentBlocklistPath(String value);

    @Description(
        "Endpoint abuse analysis paths for monitoring (multiple allowed); e.g., threshold:method:/path")
    String[] getEndpointAbusePath();

    void setEndpointAbusePath(String[] value);

    @Description("In endpoint abuse analysis, only consider variance with supporting object types")
    @Default.Boolean(false)
    Boolean getEndpointAbuseExtendedVariance();

    void setEndpointAbuseExtendedVariance(Boolean value);

    @Description("Custom variance substrings (multiple allowed); string")
    String[] getEndpointAbuseCustomVarianceSubstrings();

    void setEndpointAbuseCustomVarianceSubstrings(String[] value);

    @Description(
        "In endpoint abuse analysis, optionally use supplied suppress_recovery for violations; seconds")
    Integer getEndpointAbuseSuppressRecovery();

    void setEndpointAbuseSuppressRecovery(Integer value);

    @Description(
        "In endpoint sequence abuse analysis, optionally use supplied suppress_recovery for violations; seconds")
    Integer getEndpointSequenceAbuseSuppressRecovery();

    void setEndpointSequenceAbuseSuppressRecovery(Integer value);

    @Description(
        "Endpoint sequence patterns for monitoring (multiple allowed); e.g., threshold:method:/path:delta:method:/path")
    String[] getEndpointSequenceAbusePatterns();

    void setEndpointSequenceAbusePatterns(String[] value);

    @Description("Paths for per endpoint error rate limit monitoring; e.g., threshold:method:path ")
    String[] getPerEndpointErrorRatePaths();

    void setPerEndpointErrorRatePaths(String[] value);

    @Description(
        "In per endpoint error rate analysis, optionally use supplied suppress_recovery for violations; seconds")
    Integer getPerEndpointErrorRateAnalysisSuppressRecovery();

    void setPerEndpointErrorRateAnalysisSuppressRecovery(Integer value);

    @Description("Duration to suppress alerts for per endpoint error rate; seconds")
    @Default.Long(120)
    Long getPerEndpointErrorRateAlertSuppressionDurationSeconds();

    void setPerEndpointErrorRateAlertSuppressionDurationSeconds(Long value);

    @Description("Duration for session gap used for filtered events containing only errors")
    @Default.Long(5)
    Long getErrorSessionGapDurationMinutes();

    void setErrorSessionGapDurationMinutes(Long value);

    @Description(
        "Filter requests that result in a non-4xx status for path before analysis; e.g., method:/path")
    String[] getFilterRequestPath();

    void setFilterRequestPath(String[] value);

    @Description("Only include requests with URL host matching regex (multiple allowed); regex")
    String[] getIncludeUrlHostRegex();

    void setIncludeUrlHostRegex(String[] value);

    @Description("Load CIDR exclusion list; resource path, gcs path")
    String getCidrExclusionList();

    void setCidrExclusionList(String value);

    @Description("Gap duration to consider for sessions; minutes")
    @Default.Long(45L)
    Long getSessionGapDurationMinutes();

    void setSessionGapDurationMinutes(Long value);

    @Description("Duration to suppress alerts for sessions; seconds")
    @Default.Long(600L)
    Long getAlertSuppressionDurationSeconds();

    void setAlertSuppressionDurationSeconds(Long value);

    @Description("Ignore requests from major cloud providers (GCP, AWS)")
    @Default.Boolean(true)
    Boolean getIgnoreCloudProviderRequests();

    void setIgnoreCloudProviderRequests(Boolean value);

    @Description("Ignore requests from internal subnets (e.g., RFC1918)")
    @Default.Boolean(true)
    Boolean getIgnoreInternalRequests();

    void setIgnoreInternalRequests(Boolean value);

    @Description("Load multimode configuration file; resource path, gcs path")
    String getPipelineMultimodeConfiguration();

    void setPipelineMultimodeConfiguration(String value);

    @Description("Enable source correlator")
    @Default.Boolean(false)
    Boolean getEnableSourceCorrelator();

    void setEnableSourceCorrelator(Boolean value);

    @Description("Minimum distinct addresses for given ISP for source correlator consideration")
    @Default.Integer(250)
    Integer getSourceCorrelatorMinimumAddresses();

    void setSourceCorrelatorMinimumAddresses(Integer value);

    @Description("Percentage of addresses that created alert to result in source correlator alert")
    @Default.Double(90.00)
    Double getSourceCorrelatorAlertPercentage();

    void setSourceCorrelatorAlertPercentage(Double value);
  }

  /**
   * Build a configuration tick for HTTPRequest given pipeline options and configuration toggles
   *
   * @param options Pipeline options
   * @param toggles Analysis toggles
   * @return String
   * @throws IOException IOException
   */
  public static String buildConfigurationTick(
      HTTPRequestOptions options, HTTPRequestToggles toggles) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    if (toggles.getEnableThresholdAnalysis()) {
      b.withTransformDoc(
          new ThresholdAnalysis(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject(),
              null));
    }
    if (toggles.getEnableHardLimitAnalysis()) {
      b.withTransformDoc(
          new HardLimitAnalysis(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject(),
              null));
    }
    if (toggles.getEnableErrorRateAnalysis()) {
      b.withTransformDoc(
          new ErrorRateAnalysis(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject()));
    }
    if (toggles.getEnableUserAgentBlocklistAnalysis()) {
      b.withTransformDoc(
          new UserAgentBlocklistAnalysis(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject(),
              null));
    }
    if (toggles.getEnableEndpointAbuseAnalysis()) {
      b.withTransformDoc(
          new EndpointAbuseAnalysis(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject()));
    }
    if (toggles.getEnableSourceCorrelator()) {
      b.withTransformDoc(new SourceCorrelation.SourceCorrelator(toggles));
    }
    if (toggles.getEnableEndpointSequenceAbuseAnalysis()) {
      b.withTransformDoc(
          new EndpointSequenceAbuse(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject(),
              null));
    }
    if (toggles.getEnablePerEndpointErrorRateAnalysis()) {
      b.withTransformDoc(
          new PerEndpointErrorRateAnalysis(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject()));
    }

    return b.build();
  }

  /**
   * Given HTTPRequest pipeline options, return a configured {@link Input} class
   *
   * <p>The returned input object will be configured based on the HTTPRequest pipeline options, and
   * will have all applicable filters assigned.
   *
   * @param p Pipeline
   * @param options Pipeline options
   * @return Configured Input object
   * @throws IOException IOException
   */
  public static Input getInput(Pipeline p, HTTPRequestOptions options) throws IOException {
    // Always use a multiplexed read here, even if we will only have one element associated
    // with our input.
    Input input = new Input(options.getProject()).multiplex();

    // Ensure the cache is cleared
    toggleCache.clear();

    if (options.getPipelineMultimodeConfiguration() != null) {
      HTTPRequestMultiMode mm =
          HTTPRequestMultiMode.load(options.getPipelineMultimodeConfiguration());
      input = mm.getInput();
      // For each input element, we should have a matching entry in the service toggles
      // configuration. Iterate over and cache these entries so we can access them in the
      // analysis steps later.
      HashMap<String, HTTPRequestToggles> st = mm.getServiceToggles();
      if (st == null) {
        throw new RuntimeException("no service toggles found");
      }
      for (Map.Entry<String, HTTPRequestToggles> entry : st.entrySet()) {
        HTTPRequestToggles t = entry.getValue();
        t.setMonitoredResource(entry.getKey());
        addToggleCacheEntry(entry.getKey(), t);

        // Set the configuration tick string in the input element, since we can't initialize
        // this from JSON
        InputElement el = input.getInputElementByName(entry.getKey());
        if (el == null) {
          throw new RuntimeException(
              String.format("input element for %s not found", entry.getKey()));
        }
        if (options.getGenerateConfigurationTicksInterval() > 0) {
          el.setConfigurationTicks(
              buildConfigurationTick(options, entry.getValue()),
              options.getGenerateConfigurationTicksInterval(),
              options.getGenerateConfigurationTicksMaximum());
        }
      }
    } else {
      // We are using pipeline options based input configuration. Start with a new input element
      // based on that configuration, we will essentially simulate a multimode configuration with
      // a single element specified.
      //
      // We will simply use the monitored resource set in the pipeline options as the element name,
      // which in turn will be reflected in alerts created.
      //
      // Since we are using pipeline options for all configuration here, we can also use them
      // to build the configuration tick.
      HTTPRequestToggles t = HTTPRequestToggles.fromPipelineOptions(options);
      t.setMonitoredResource(options.getMonitoredResourceIndicator());
      InputElement e =
          InputElement.fromPipelineOptions(
              options.getMonitoredResourceIndicator(), options, buildConfigurationTick(options, t));
      e.setParserConfiguration(ParserCfg.fromInputOptions(options))
          .setEventFilter(t.toStandardFilter());
      input.withInputElement(e);
      toggleCache.put(options.getMonitoredResourceIndicator(), t);
    }

    return input;
  }

  /**
   * Read from a configured {@link Input} object, returning a PCollectionTuple of events
   *
   * <p>The PCollectionTuple that is returned contains PCollections tagged by resource indicator.
   * Each PCollection contains only events and uses the resource indicator as the TupleTag id.
   *
   * @param p Pipeline
   * @param input Configured {@link Input} object
   * @param options Pipeline options
   * @return PCollectionTuple with each event collection tagged by resource indicator
   */
  public static PCollectionTuple readInput(Pipeline p, Input input, HTTPRequestOptions options) {
    // Perform the multiplexed read operations
    PCollection<KV<String, Event>> col = p.apply("input", input.multiplexRead());
    TupleTagList tupleTagList = TupleTagList.empty();

    for (HTTPRequestToggles toggle : toggleCache.values()) {
      tupleTagList = tupleTagList.and(tagForResourceIndicator(toggle.getMonitoredResource()));
    }

    PCollectionTuple allResources =
        col.apply(
            "filter and tag each monitored resource",
            ParDo.of(
                    new DoFn<KV<String, Event>, Event>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        KV<String, Event> e = c.element();
                        c.output(tagForResourceIndicator(e.getKey()), e.getValue());
                      }
                    })
                .withOutputTags(new TupleTag<Event>(), tupleTagList));

    return allResources;
  }

  /**
   * Expand the input collection tuple, executing analysis transforms for each element
   *
   * @param p Pipeline
   * @param input PCollectionTuple using resource name as tag id
   * @param options Pipeline options
   * @return Flattened alerts in the global window
   */
  public static PCollection<Alert> expandInputMap(
      Pipeline p, PCollectionTuple input, HTTPRequestOptions options) {
    PCollectionList<Alert> resultsList = PCollectionList.empty(p);

    for (HTTPRequestToggles toggles : toggleCache.values()) {
      String name = toggles.getMonitoredResource();
      final TupleTag<Event> tag = tagForResourceIndicator(name);
      resultsList =
          resultsList
              .and(
                  input
                      .get(tag)
                      .apply(
                          String.format("pre-analysis filter %s", name),
                          new HTTPRequestElementFilter(toggleCache.get(name)))
                      .apply(
                          String.format("analyze %s", name),
                          new HTTPRequestAnalysis(options, toggleCache.get(name)))
                      .apply(
                          String.format("tag %s", name),
                          ParDo.of(new HTTPRequestResourceTag(name))))
              .and(
                  input
                      .get(tag)
                      .apply(
                          String.format("cfgtick process %s", name),
                          ParDo.of(new CfgTickProcessor("httprequest-cfgtick")))
                      .apply(
                          String.format("cfgtick tag %s", name),
                          ParDo.of(new HTTPRequestResourceTag(name)))
                      .apply(
                          String.format("cfgtick globaltriggers %s", name),
                          new GlobalTriggers<Alert>(5)));
    }

    return resultsList.apply("flatten all output", Flatten.<Alert>pCollections());
  }

  private static void standardOutput(PCollection<Alert> alerts, HTTPRequestOptions options) {
    alerts
        .apply("output format", ParDo.of(new AlertFormatter(options)))
        .apply("output convert", MapElements.via(new AlertFormatter.AlertToString()))
        .apply("output", OutputOptions.compositeOutput(options));
  }

  private static void runHTTPRequest(HTTPRequestOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    Input input = getInput(p, options);
    PCollectionTuple inputMap = readInput(p, input, options);
    standardOutput(expandInputMap(p, inputMap, options), options);

    p.run();
  }

  /**
   * Helper to create the tuple tag for a resource
   *
   * <p>This exists because we need to prevent type erasure of the tagged output.
   */
  private static TupleTag<Event> tagForResourceIndicator(String name) {
    return new TupleTag<Event>(name) {
      private static final long serialVersionUID = 1L;
    };
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   * @throws Exception Exception
   */
  public static void main(String[] args) throws Exception {
    PipelineOptionsFactory.register(HTTPRequestOptions.class);
    HTTPRequestOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(HTTPRequestOptions.class);
    runHTTPRequest(options);
  }
}
