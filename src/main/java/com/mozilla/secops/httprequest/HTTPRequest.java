package com.mozilla.secops.httprequest;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.DetectNat;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.FileUtil;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.Stats;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterPayloadOr;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
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
import org.apache.beam.sdk.values.PCollectionView;
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

  /**
   * Composite transform to parse a {@link PCollection} containing events as strings and emit a
   * {@link PCollection} of {@link Event} objects.
   *
   * <p>This transform currently discards events that do not contain the HTTP_REQUEST normalized
   * field.
   */
  public static class Parse extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private final String[] filterRequestPath;
    private final String cidrExclusionList;
    private final String[] includeUrlHostRegex;
    private final Boolean ignoreCp;
    private final Boolean ignoreInternal;
    private ParserCfg cfg;

    /**
     * Static initializer for {@link Parse} transform
     *
     * @param options Pipeline options
     */
    public Parse(HTTPRequestOptions options) {
      filterRequestPath = options.getFilterRequestPath();
      cidrExclusionList = options.getCidrExclusionList();
      includeUrlHostRegex = options.getIncludeUrlHostRegex();
      ignoreCp = options.getIgnoreCloudProviderRequests();
      ignoreInternal = options.getIgnoreInternalRequests();
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter().passConfigurationTicks().setWantUTC(true);
      EventFilterRule rule = new EventFilterRule().wantNormalizedType(Normalized.Type.HTTP_REQUEST);
      if (filterRequestPath != null) {
        for (String s : filterRequestPath) {
          String[] parts = s.split(":");
          if (parts.length != 2) {
            throw new IllegalArgumentException(
                "invalid format for filter path, must be <method>:<path>");
          }
          rule.except(
              new EventFilterRule()
                  .wantNormalizedType(Normalized.Type.HTTP_REQUEST)
                  .addPayloadFilter(
                      new EventFilterPayload()
                          .withStringMatch(
                              EventFilterPayload.StringProperty.NORMALIZED_REQUESTMETHOD, parts[0])
                          .withStringMatch(
                              EventFilterPayload.StringProperty.NORMALIZED_URLREQUESTPATH,
                              parts[1]))
                  .addPayloadFilter(
                      new EventFilterPayloadOr()
                          .addPayloadFilter(
                              new EventFilterPayload()
                                  .withIntegerRangeMatch(
                                      EventFilterPayload.IntegerProperty.NORMALIZED_REQUESTSTATUS,
                                      0,
                                      399))
                          .addPayloadFilter(
                              new EventFilterPayload()
                                  .withIntegerRangeMatch(
                                      EventFilterPayload.IntegerProperty.NORMALIZED_REQUESTSTATUS,
                                      500,
                                      Integer.MAX_VALUE))));
        }
      }
      if (includeUrlHostRegex != null) {
        EventFilterPayloadOr orFilter = new EventFilterPayloadOr();
        for (String s : includeUrlHostRegex) {
          orFilter.addPayloadFilter(
              new EventFilterPayload()
                  .withStringRegexMatch(
                      EventFilterPayload.StringProperty.NORMALIZED_URLREQUESTHOST, s));
        }
        rule.addPayloadFilter(orFilter);
      }
      filter.addRule(rule);
      PCollection<Event> parsed =
          col.apply(
              ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)));
      int exclmask = 0;
      if (cidrExclusionList != null) {
        exclmask |= CidrUtil.CIDRUTIL_FILE;
      }
      if (ignoreCp) {
        exclmask |= CidrUtil.CIDRUTIL_CLOUDPROVIDERS;
      }
      if (ignoreInternal) {
        exclmask |= CidrUtil.CIDRUTIL_INTERNAL;
      }
      if (exclmask != 0) {
        return parsed.apply(
            "cidr exclusion",
            ParDo.of(CidrUtil.excludeNormalizedSourceAddresses(exclmask, cidrExclusionList)));
      }
      return parsed;
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
   * Key requests for session analysis and window into sessions
   *
   * <p>Windows are configured to fire early every 10 seconds, and accumulate panes.
   */
  public static class KeyAndWindowForSessionsFireEarly
      extends PTransform<PCollection<Event>, PCollection<KV<String, ArrayList<String>>>> {
    private static final long serialVersionUID = 1L;

    private final Long gapDurationMinutes;
    private final Long paneFiringDelaySeconds = 10L;

    public KeyAndWindowForSessionsFireEarly(HTTPRequestOptions options) {
      gapDurationMinutes = options.getSessionGapDurationMinutes();
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
    private final Boolean enableIprepdDatastoreWhitelist;
    private final String iprepdDatastoreWhitelistProject;

    /**
     * Static initializer for {@link ErrorRateAnalysis}
     *
     * @param options Pipeline options
     */
    public ErrorRateAnalysis(HTTPRequestOptions options) {
      maxErrorRate = options.getMaxClientErrorRate();
      monitoredResource = options.getMonitoredResourceIndicator();
      enableIprepdDatastoreWhitelist = options.getOutputIprepdEnableDatastoreWhitelist();
      iprepdDatastoreWhitelistProject = options.getOutputIprepdDatastoreWhitelistProject();
    }

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
                      a.addMetadata("category", "error_rate");
                      a.addMetadata("sourceaddress", c.element().getKey());

                      if (enableIprepdDatastoreWhitelist) {
                        try {
                          IprepdIO.addMetadataIfIpWhitelisted(
                              c.element().getKey(), a, iprepdDatastoreWhitelistProject);
                        } catch (IOException exc) {
                          return;
                        }
                      }

                      a.addMetadata("error_count", c.element().getValue().toString());
                      a.addMetadata("error_threshold", maxErrorRate.toString());
                      a.setNotifyMergeKey("error_count");
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

  /** Transform for analysis of hard per-source request count limit within fixed window */
  public static class HardLimitAnalysis extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final Long maxCount;
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreWhitelist;
    private final String iprepdDatastoreWhitelistProject;
    private PCollectionView<Map<String, Boolean>> natView = null;

    private Logger log;

    /**
     * Static initializer for {@link HardLimitAnalysis}
     *
     * @param options Pipeline options
     */
    public HardLimitAnalysis(HTTPRequestOptions options) {
      maxCount = options.getHardLimitRequestCount();
      monitoredResource = options.getMonitoredResourceIndicator();
      enableIprepdDatastoreWhitelist = options.getOutputIprepdEnableDatastoreWhitelist();
      iprepdDatastoreWhitelistProject = options.getOutputIprepdDatastoreWhitelistProject();
      log = LoggerFactory.getLogger(HardLimitAnalysis.class);
    }

    /**
     * Static initializer for {@link HardLimitAnalysis}
     *
     * @param options Pipeline options
     * @param natView Use {@link DetectNat} view during hard limit analysis
     */
    public HardLimitAnalysis(
        HTTPRequestOptions options, PCollectionView<Map<String, Boolean>> natView) {
      this(options);
      this.natView = natView;
    }

    public String getTransformDoc() {
      return String.format(
          "Alert if single source address makes more than %d requests in a 1 minute window.",
          maxCount);
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      if (natView == null) {
        // If natView was not set then we just create an empty view for use as the side input
        natView = DetectNat.getEmptyView(input.getPipeline());
      }
      return input
          .apply(
              "hard limit per client count",
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
          .apply(Count.<String>perElement())
          .apply(
              "per-source hard limit analysis",
              ParDo.of(
                      new DoFn<KV<String, Long>, Alert>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c, BoundedWindow w) {
                          Map<String, Boolean> nv = c.sideInput(natView);
                          if (c.element().getValue() <= maxCount) {
                            return;
                          }
                          Boolean isNat = nv.get(c.element().getKey());
                          if (isNat != null && isNat) {
                            log.info(
                                "{}: detectnat: skipping result emission for {}",
                                w.toString(),
                                c.element().getKey());
                            return;
                          }
                          Alert a = new Alert();
                          a.setSummary(
                              String.format(
                                  "%s httprequest hard_limit %s %d",
                                  monitoredResource, c.element().getKey(), c.element().getValue()));
                          a.setCategory("httprequest");
                          a.addMetadata("category", "hard_limit");
                          a.addMetadata("sourceaddress", c.element().getKey());

                          try {
                            if (enableIprepdDatastoreWhitelist) {
                              IprepdIO.addMetadataIfIpWhitelisted(
                                  c.element().getKey(), a, iprepdDatastoreWhitelistProject);
                            }
                          } catch (IOException exc) {
                            return;
                          }

                          a.addMetadata("count", c.element().getValue().toString());
                          a.addMetadata("request_threshold", maxCount.toString());
                          a.setNotifyMergeKey("hard_limit_count");
                          a.addMetadata(
                              "window_timestamp", (new DateTime(w.maxTimestamp())).toString());
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
  public static class UserAgentBlacklistAnalysis
      extends PTransform<PCollection<Event>, PCollection<Alert>> implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreWhitelist;
    private final String iprepdDatastoreWhitelistProject;
    private final String uaBlacklistPath;

    private PCollectionView<Map<String, Boolean>> natView = null;

    private Logger log;

    /**
     * Initialize new {@link UserAgentBlacklistAnalysis}
     *
     * @param options Pipeline options
     */
    public UserAgentBlacklistAnalysis(HTTPRequestOptions options) {
      monitoredResource = options.getMonitoredResourceIndicator();
      enableIprepdDatastoreWhitelist = options.getOutputIprepdEnableDatastoreWhitelist();
      iprepdDatastoreWhitelistProject = options.getOutputIprepdDatastoreWhitelistProject();
      uaBlacklistPath = options.getUserAgentBlacklistPath();
      log = LoggerFactory.getLogger(UserAgentBlacklistAnalysis.class);
    }

    /**
     * Initialize new {@link UserAgentBlacklistAnalysis}
     *
     * @param options Pipeline options
     * @param natView Use {@link DetectNat} view during analysis
     */
    public UserAgentBlacklistAnalysis(
        HTTPRequestOptions options, PCollectionView<Map<String, Boolean>> natView) {
      this(options);
      this.natView = natView;
    }

    public String getTransformDoc() {
      return new String(
          "Alert if client makes request with user agent that matches entry in blacklist.");
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

                    private ArrayList<Pattern> uaRegex;

                    @Setup
                    public void setup() throws IOException {
                      ArrayList<String> in = FileUtil.fileReadLines(uaBlacklistPath);
                      uaRegex = new ArrayList<Pattern>();
                      for (String i : in) {
                        uaRegex.add(Pattern.compile(i));
                      }
                    }

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Normalized n = c.element().getNormalized();

                      String ua = n.getUserAgent();
                      if (ua == null) {
                        return;
                      }
                      for (Pattern p : uaRegex) {
                        if (p.matcher(ua).matches()) {
                          c.output(KV.of(n.getSourceAddress(), ua));
                          return;
                        }
                      }
                    }
                  }))
          .apply(GroupByKey.<String, String>create())
          .apply(
              "user agent blacklist analysis",
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
                            return;
                          }

                          Alert a = new Alert();
                          a.setSummary(
                              String.format(
                                  "%s httprequest useragent_blacklist %s",
                                  monitoredResource, saddr));
                          a.setCategory("httprequest");
                          a.addMetadata("category", "useragent_blacklist");
                          a.addMetadata("sourceaddress", saddr);

                          try {
                            if (enableIprepdDatastoreWhitelist) {
                              IprepdIO.addMetadataIfIpWhitelisted(
                                  saddr, a, iprepdDatastoreWhitelistProject);
                            }
                          } catch (IOException exc) {
                            return;
                          }

                          a.setNotifyMergeKey("useragent_blacklist");
                          a.addMetadata(
                              "window_timestamp", (new DateTime(w.maxTimestamp())).toString());

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
    private final Boolean enableIprepdDatastoreWhitelist;
    private final Boolean varianceSupportingOnly;
    private final String[] customVarianceSubstrings;
    private final String iprepdDatastoreWhitelistProject;
    private final Integer suppressRecovery;
    private final Long sessionGapDurationMinutes;

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
     * @param options Pipeline options
     */
    public EndpointAbuseAnalysis(HTTPRequestOptions options) {
      log = LoggerFactory.getLogger(EndpointAbuseAnalysis.class);

      monitoredResource = options.getMonitoredResourceIndicator();
      enableIprepdDatastoreWhitelist = options.getOutputIprepdEnableDatastoreWhitelist();
      iprepdDatastoreWhitelistProject = options.getOutputIprepdDatastoreWhitelistProject();
      varianceSupportingOnly = options.getEndpointAbuseExtendedVariance();
      suppressRecovery = options.getEndpointAbuseSuppressRecovery();
      customVarianceSubstrings = options.getEndpointAbuseCustomVarianceSubstrings();
      sessionGapDurationMinutes = options.getSessionGapDurationMinutes();

      String[] cfgEndpoints = options.getEndpointAbusePath();
      endpoints = new EndpointAbuseEndpointInfo[cfgEndpoints.length];
      for (int i = 0; i < cfgEndpoints.length; i++) {
        String[] parts = cfgEndpoints[i].split(":");
        if (parts.length != 3) {
          throw new IllegalArgumentException(
              "invalid format for abuse endpoint path, must be <int>:<method>:<path>");
        }
        EndpointAbuseEndpointInfo ninfo = new EndpointAbuseEndpointInfo();
        ninfo.threshold = new Integer(parts[0]);
        ninfo.method = parts[1];
        ninfo.path = parts[2];
        endpoints[i] = ninfo;
      }
    }

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
                      Boolean basicVariance = false;
                      Boolean extendedVariance = false;

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
                      a.addMetadata("category", "endpoint_abuse");
                      a.addMetadata("sourceaddress", remoteAddress);

                      try {
                        if (enableIprepdDatastoreWhitelist) {
                          IprepdIO.addMetadataIfIpWhitelisted(
                              remoteAddress, a, iprepdDatastoreWhitelistProject);
                        }
                      } catch (IOException exc) {
                        return;
                      }

                      if (suppressRecovery != null) {
                        IprepdIO.addMetadataSuppressRecovery(suppressRecovery, a);
                      }

                      a.addMetadata("endpoint", comparePath);
                      a.addMetadata("method", compareMethod);
                      a.addMetadata("count", Integer.toString(count));
                      a.addMetadata("useragent", userAgent);
                      a.setNotifyMergeKey("endpoint_abuse");
                      a.addMetadata(
                          "window_timestamp", (new DateTime(w.maxTimestamp())).toString());
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
          .apply(ParDo.of(new AlertSuppressorCount(600L))); // 10 mins, should be configurable
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
    private final String monitoredResource;
    private final Boolean enableIprepdDatastoreWhitelist;
    private final String iprepdDatastoreWhitelistProject;
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
      this.enableIprepdDatastoreWhitelist = options.getOutputIprepdEnableDatastoreWhitelist();
      this.iprepdDatastoreWhitelistProject = options.getOutputIprepdDatastoreWhitelistProject();
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
                      if (c.element().getValue() > 1) {
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
                            a.addMetadata("category", "threshold_analysis");
                            a.addMetadata("sourceaddress", c.element().getKey());

                            try {
                              if (enableIprepdDatastoreWhitelist) {
                                IprepdIO.addMetadataIfIpWhitelisted(
                                    c.element().getKey(), a, iprepdDatastoreWhitelistProject);
                              }
                            } catch (IOException exc) {
                              return;
                            }

                            a.addMetadata("mean", sOutput.getMean().toString());
                            a.addMetadata("count", c.element().getValue().toString());
                            a.addMetadata("threshold_modifier", thresholdModifier.toString());
                            a.setNotifyMergeKey("threshold_analysis");
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
                  .withSideInputs(wStats, natView));
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

    @Description("Enable hard limit analysis")
    @Default.Boolean(false)
    Boolean getEnableHardLimitAnalysis();

    void setEnableHardLimitAnalysis(Boolean value);

    @Description("Enable user agent blacklist analysis")
    @Default.Boolean(false)
    Boolean getEnableUserAgentBlacklistAnalysis();

    void setEnableUserAgentBlacklistAnalysis(Boolean value);

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

    @Description("Maximum permitted client error rate per window")
    @Default.Long(30L)
    Long getMaxClientErrorRate();

    void setMaxClientErrorRate(Long value);

    @Description("Enable NAT detection for threshold analysis")
    @Default.Boolean(false)
    Boolean getNatDetection();

    void setNatDetection(Boolean value);

    @Description(
        "Path to load user agent blacklist from for UA blacklist analysis; resource path, gcs path")
    String getUserAgentBlacklistPath();

    void setUserAgentBlacklistPath(String value);

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

    @Description("Ignore requests from whitelisted cloud providers (GCP, AWS)")
    @Default.Boolean(true)
    Boolean getIgnoreCloudProviderRequests();

    void setIgnoreCloudProviderRequests(Boolean value);

    @Description("Ignore requests from internal subnets (e.g., RFC1918)")
    @Default.Boolean(true)
    Boolean getIgnoreInternalRequests();

    void setIgnoreInternalRequests(Boolean value);
  }

  /**
   * Build a configuration tick for HTTPRequest given pipeline options
   *
   * @param options Pipeline options
   * @return String
   */
  public static String buildConfigurationTick(HTTPRequestOptions options) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    if (options.getEnableThresholdAnalysis()) {
      b.withTransformDoc(new ThresholdAnalysis(options, null));
    }
    if (options.getEnableHardLimitAnalysis()) {
      b.withTransformDoc(new HardLimitAnalysis(options, null));
    }
    if (options.getEnableErrorRateAnalysis()) {
      b.withTransformDoc(new ErrorRateAnalysis(options));
    }
    if (options.getEnableUserAgentBlacklistAnalysis()) {
      b.withTransformDoc(new UserAgentBlacklistAnalysis(options, null));
    }
    if (options.getEnableEndpointAbuseAnalysis()) {
      b.withTransformDoc(new EndpointAbuseAnalysis(options));
    }

    return b.build();
  }

  private static void runHTTPRequest(HTTPRequestOptions options) {
    Pipeline p = Pipeline.create(options);

    PCollection<Event> events;
    try {
      events =
          p.apply("input", Input.compositeInputAdapter(options, buildConfigurationTick(options)))
              .apply("parse", new Parse(options));
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }

    PCollectionList<Alert> resultsList = PCollectionList.empty(p);

    if (options.getEnableThresholdAnalysis()
        || options.getEnableErrorRateAnalysis()
        || options.getEnableHardLimitAnalysis()) {
      PCollection<Event> fwEvents = events.apply("window for fixed", new WindowForFixed());

      PCollectionView<Map<String, Boolean>> natView = null;
      if (options.getNatDetection()) {
        natView = DetectNat.getView(fwEvents);
      }

      if (options.getEnableThresholdAnalysis()) {
        resultsList =
            resultsList.and(
                fwEvents
                    .apply("threshold analysis", new ThresholdAnalysis(options, natView))
                    .apply("threshold analysis global", new GlobalTriggers<Alert>(5)));
      }

      if (options.getEnableHardLimitAnalysis()) {
        resultsList =
            resultsList.and(
                fwEvents
                    .apply("hard limit analysis", new HardLimitAnalysis(options, natView))
                    .apply("hard limit analysis global", new GlobalTriggers<Alert>(5)));
      }

      if (options.getEnableErrorRateAnalysis()) {
        resultsList =
            resultsList.and(
                fwEvents
                    .apply("error rate analysis", new ErrorRateAnalysis(options))
                    .apply("error rate analysis global", new GlobalTriggers<Alert>(5)));
      }

      if (options.getEnableUserAgentBlacklistAnalysis()) {
        resultsList =
            resultsList.and(
                fwEvents
                    .apply(
                        "ua blacklist analysis", new UserAgentBlacklistAnalysis(options, natView))
                    .apply("ua blacklist analysis global", new GlobalTriggers<Alert>(5)));
      }
    }

    if (options.getEnableEndpointAbuseAnalysis()) {
      resultsList =
          resultsList.and(
              events
                  .apply(
                      "key and window for sessions fire early",
                      new KeyAndWindowForSessionsFireEarly(options))
                  // No requirement for follow up application of GlobalTriggers here since
                  // EndpointAbuseAnalysis will do this for us
                  .apply("endpoint abuse analysis", new EndpointAbuseAnalysis(options)));
    }

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      resultsList =
          resultsList.and(
              events
                  .apply(
                      "cfgtick processor",
                      ParDo.of(new CfgTickProcessor("httprequest-cfgtick", "category")))
                  .apply(new GlobalTriggers<Alert>(5)));
    }

    resultsList
        .apply("flatten output", Flatten.<Alert>pCollections())
        .apply("output format", ParDo.of(new AlertFormatter(options)))
        .apply("output", OutputOptions.compositeOutput(options));

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
