package com.mozilla.secops.httprequest;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.SourceCorrelation;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.httprequest.heuristics.EndpointAbuseAnalysis;
import com.mozilla.secops.httprequest.heuristics.EndpointSequenceAbuse;
import com.mozilla.secops.httprequest.heuristics.ErrorRateAnalysis;
import com.mozilla.secops.httprequest.heuristics.HardLimitAnalysis;
import com.mozilla.secops.httprequest.heuristics.PerEndpointErrorRateAnalysis;
import com.mozilla.secops.httprequest.heuristics.SessionLimitAnalysis;
import com.mozilla.secops.httprequest.heuristics.StatusCodeRateAnalysis;
import com.mozilla.secops.httprequest.heuristics.ThresholdAnalysis;
import com.mozilla.secops.httprequest.heuristics.UserAgentBlocklistAnalysis;
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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Filter;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.SerializableFunction;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
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
import org.joda.time.Duration;

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
          || toggles.getEnableEndpointSequenceAbuseAnalysis()
          || toggles.getEnableStatusCodeRateAnalysis()) {
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
        if (toggles.getEnableStatusCodeRateAnalysis()) {
          resultsList =
              resultsList.and(
                  fwEvents
                      .apply(
                          "status code rate analysis",
                          new StatusCodeRateAnalysis(
                              toggles,
                              enableIprepdDatastoreExemptions,
                              iprepdDatastoreExemptionsProject))
                      .apply(
                          "status code rate analysis global triggers",
                          new GlobalTriggers<Alert>(5)));
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
      if (toggles.getEnableSessionLimitAnalysis()) {
        resultsList =
            resultsList.and(
                events
                    .apply(
                        "key and window for sessions fire early (session limit)",
                        new KeyAndWindowForSessionsFireEarly(
                            toggles.getSessionGapDurationMinutes()))
                    .apply(
                        "session limit analysis",
                        new SessionLimitAnalysis(
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

    @Description("Enable status code rate analysis")
    @Default.Boolean(false)
    Boolean getEnableStatusCodeRateAnalysis();

    void setEnableStatusCodeRateAnalysis(Boolean value);

    @Description("Maximum permitted responses with a given status code per client in a window")
    @Default.Long(60L)
    Long getMaxClientStatusCodeRate();

    void setMaxClientStatusCodeRate(Long value);

    @Description("HTTP status code to limit the number of responses of")
    Integer getStatusCodeRateAnalysisCode();

    void setStatusCodeRateAnalysisCode(Integer value);

    @Description("Enable session limit analysis")
    @Default.Boolean(false)
    Boolean getEnableSessionLimitAnalysis();

    void setEnableSessionLimitAnalysis(Boolean value);

    @Description(
        "Session limit analysis paths for monitoring (multiple allowed); e.g., monitor_only_threshold:alerting_threshold:method:/path")
    String[] getSessionLimitAnalysisPaths();

    void setSessionLimitAnalysisPaths(String[] value);

    @Description(
        "In session limit analysis, optionally use supplied suppress_recovery for violations; seconds")
    Integer getSessionLimitAnalysisSuppressRecovery();

    void setSessionLimitAnalysisSuppressRecovery(Integer value);
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
    if (toggles.getEnableStatusCodeRateAnalysis()) {
      b.withTransformDoc(
          new StatusCodeRateAnalysis(
              toggles,
              options.getOutputIprepdEnableDatastoreExemptions(),
              options.getOutputIprepdDatastoreExemptionsProject()));
    }
    if (toggles.getEnableSessionLimitAnalysis()) {
      b.withTransformDoc(
          new SessionLimitAnalysis(
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
