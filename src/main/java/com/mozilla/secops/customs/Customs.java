package com.mozilla.secops.customs;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.Values;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Sessions;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements various rate limiting and analysis heuristics on {@link
 * com.mozilla.secops.parser.FxaAuth} streams
 */
public class Customs implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Generic rate limiting detector driven by {@link CustomsCfgEntry} */
  public static class Detector extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final String detectorName;
    private final String monitoredResource;
    private final CustomsCfgEntry cfg;

    private Logger log;

    /**
     * Initialize detector
     *
     * @param detectorName Descriptive name for detector instance
     * @param cfg Configuration for detector
     * @param monitoredResource Monitored resource name
     */
    public Detector(String detectorName, CustomsCfgEntry cfg, String monitoredResource) {
      log = LoggerFactory.getLogger(Detector.class);
      log.info("initializing new detector, {}", detectorName);
      this.cfg = cfg;
      this.detectorName = detectorName;
      this.monitoredResource = monitoredResource;
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      return col.apply(detectorName, new RateLimitAnalyzer(detectorName, cfg, monitoredResource));
    }
  }

  /** Analyze input stream for account creation abuse */
  public static class AccountCreationAbuse
      extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final String monitoredResource;
    private final int sessionGapSeconds = 1800;
    private final Integer sessionCreationLimit;
    private final int distanceThreshold;
    private final Double distanceRatio;
    private final Integer accountAbuseSuppressRecovery;

    /**
     * Initialize account creation abuse
     *
     * @param options Pipeline options
     */
    public AccountCreationAbuse(CustomsOptions options) {
      monitoredResource = options.getMonitoredResourceIndicator();
      sessionCreationLimit = options.getAccountCreationSessionLimit();
      distanceThreshold = options.getAccountCreationDistanceThreshold();
      distanceRatio = options.getAccountCreationDistanceRatio();
      accountAbuseSuppressRecovery = options.getAccountAbuseSuppressRecovery();
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      PCollectionList<Alert> resultsList = PCollectionList.empty(col.getPipeline());

      // Apply initial filtering and keying
      PCollection<KV<String, Event>> keyed = CustomsAccountCreation.keyCreationEvents(col);

      // Window into sessions and apply limit detection
      resultsList =
          resultsList.and(
              keyed
                  .apply(
                      "account creation sessions",
                      Window.<KV<String, Event>>into(
                              Sessions.withGapDuration(Duration.standardSeconds(sessionGapSeconds)))
                          .triggering(
                              Repeatedly.forever(
                                  AfterWatermark.pastEndOfWindow()
                                      .withEarlyFirings(
                                          AfterProcessingTime.pastFirstElementInPane()
                                              .plusDelayOf(Duration.standardMinutes(5)))))
                          .withAllowedLateness(Duration.ZERO)
                          .accumulatingFiredPanes())
                  .apply("account creation gbk", GroupByKey.<String, Event>create())
                  .apply(
                      "account creation",
                      ParDo.of(
                          new CustomsAccountCreation(
                              monitoredResource,
                              sessionCreationLimit,
                              accountAbuseSuppressRecovery)))
                  .apply(
                      "account creation global windows", new GlobalTriggers<KV<String, Alert>>(5))
                  .apply(
                      "account creation suppression",
                      ParDo.of(new AlertSuppressorCount(new Long(sessionGapSeconds)))));

      // Alerts for distributed string distance
      resultsList =
          resultsList.and(
              keyed
                  .apply("account creation dist values", Values.<Event>create())
                  .apply(
                      "account creation dist key for domain",
                      ParDo.of(
                          new DoFn<Event, KV<String, Event>>() {
                            private static final long serialVersionUID = 1L;

                            @ProcessElement
                            public void processElement(ProcessContext c) {
                              Event e = c.element();

                              String[] parts = CustomsUtil.authGetEmail(e).split("@");
                              if (parts.length != 2) {
                                return;
                              }
                              c.output(KV.of(parts[1], e));
                            }
                          }))
                  .apply(
                      "account creation dist fixed windows",
                      Window.<KV<String, Event>>into(FixedWindows.of(Duration.standardMinutes(30))))
                  .apply("account creation dist gbk", GroupByKey.<String, Event>create())
                  .apply(
                      "account creation dist",
                      ParDo.of(
                          new CustomsAccountCreationDist(
                              monitoredResource, distanceThreshold, distanceRatio)))
                  .apply("account creation dist global windows", new GlobalTriggers<Alert>(5)));

      return resultsList.apply("account creation flatten output", Flatten.<Alert>pCollections());
    }
  }

  /**
   * High level transform for invoking all rate limit detector instances given the customs
   * configuration
   */
  public static class Detectors extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final CustomsCfg cfg;
    private final String monitoredResource;

    /**
     * Initialize new flattening rate limit detectors instance
     *
     * @param cfg Customs configuration
     * @param options Pipeline options
     */
    public Detectors(CustomsCfg cfg, CustomsOptions options) {
      this.cfg = cfg;
      monitoredResource = options.getMonitoredResourceIndicator();
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      PCollectionList<Alert> alerts = PCollectionList.empty(col.getPipeline());
      for (Map.Entry<String, CustomsCfgEntry> entry : cfg.getDetectors().entrySet()) {
        String detectorName = entry.getKey();
        CustomsCfgEntry detectorCfg = entry.getValue();
        alerts =
            alerts.and(
                col.apply(
                    detectorName, new Detector(detectorName, detectorCfg, monitoredResource)));
      }
      PCollection<Alert> ret =
          alerts.apply("flatten rate limit output", Flatten.<Alert>pCollections());
      return ret;
    }
  }

  /** Runtime options for {@link Customs} pipeline. */
  public interface CustomsOptions extends PipelineOptions, IOOptions {
    @Description("path to customs rate limit configuration; resource path")
    @Default.String("/customs/customsdefault.json")
    String getConfigurationResourcePath();

    void setConfigurationResourcePath(String value);

    @Description("Enable customs rate limit detectors")
    @Default.Boolean(true)
    Boolean getEnableRateLimitDetectors();

    void setEnableRateLimitDetectors(Boolean value);

    @Description("Enable account creation abuse detector")
    @Default.Boolean(false)
    Boolean getEnableAccountCreationAbuseDetector();

    void setEnableAccountCreationAbuseDetector(Boolean value);

    @Description("Account creation limit for session abuse analysis")
    @Default.Integer(5)
    Integer getAccountCreationSessionLimit();

    void setAccountCreationSessionLimit(Integer value);

    @Description("Account creation threshold for string distance analysis")
    @Default.Integer(5)
    Integer getAccountCreationDistanceThreshold();

    void setAccountCreationDistanceThreshold(Integer value);

    @Description("Account creation string distance upper ratio")
    @Default.Double(0.35)
    Double getAccountCreationDistanceRatio();

    void setAccountCreationDistanceRatio(Double value);

    @Description(
        "For account abuse, optionally use supplied suppress_recovery for violations; seconds")
    Integer getAccountAbuseSuppressRecovery();

    void setAccountAbuseSuppressRecovery(Integer value);
  }

  /**
   * Analysis entry point for Customs pipeline
   *
   * @param p Pipeline
   * @param input Input data
   * @param options CustomsOptions
   * @return {@link PCollection} containing {@link Alert} objects
   */
  public static PCollection<Alert> executePipeline(
      Pipeline p, PCollection<String> input, CustomsOptions options) throws IOException {
    CustomsCfg cfg = CustomsCfg.loadFromResource(options.getConfigurationResourcePath());

    PCollection<Event> events =
        input.apply(
            "parse",
            ParDo.of(new ParserDoFn().withConfiguration(ParserCfg.fromInputOptions(options))));

    PCollectionList<Alert> resultsList = PCollectionList.empty(p);

    if (options.getEnableRateLimitDetectors()) {
      resultsList =
          resultsList.and(events.apply("rate limit detectors", new Detectors(cfg, options)));
    }
    if (options.getEnableAccountCreationAbuseDetector()) {
      resultsList =
          resultsList.and(
              events.apply("account creation abuse", new AccountCreationAbuse(options)));
    }
    return resultsList.apply("flatten all output", Flatten.<Alert>pCollections());
  }

  private static void runCustoms(CustomsOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input = p.apply("input", new CompositeInput(options));
    PCollection<Alert> alerts = executePipeline(p, input, options);

    alerts
        .apply("alert formatter", ParDo.of(new AlertFormatter(options)))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) throws IOException {
    PipelineOptionsFactory.register(CustomsOptions.class);
    CustomsOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(CustomsOptions.class);
    runCustoms(options);
  }
}
