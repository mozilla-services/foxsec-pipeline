package com.mozilla.secops.customs;

import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
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

/**
 * Implements various rate limiting and analysis heuristics on {@link
 * com.mozilla.secops.parser.FxaAuth} streams
 */
public class Customs implements Serializable {
  private static final long serialVersionUID = 1L;

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

  /** Runtime options for {@link Customs} pipeline. */
  public interface CustomsOptions extends PipelineOptions, IOOptions {
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
   * Build a configuration tick for Customs given pipeline options
   *
   * @param options Pipeline options
   * @return String
   */
  public static String buildConfigurationTick(CustomsOptions options) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    if (options.getEnableAccountCreationAbuseDetector()) {
      b.withTransformDoc(
          new CustomsAccountCreation(
              options.getMonitoredResourceIndicator(),
              options.getAccountCreationSessionLimit(),
              options.getAccountAbuseSuppressRecovery()));

      b.withTransformDoc(
          new CustomsAccountCreationDist(
              options.getMonitoredResourceIndicator(),
              options.getAccountCreationDistanceThreshold(),
              options.getAccountCreationDistanceRatio()));
    }

    return b.build();
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
    PCollection<Event> events =
        input.apply(
            "parse",
            ParDo.of(new ParserDoFn().withConfiguration(ParserCfg.fromInputOptions(options))));

    PCollectionList<Alert> resultsList = PCollectionList.empty(p);

    if (options.getEnableAccountCreationAbuseDetector()) {
      resultsList =
          resultsList.and(
              events.apply("account creation abuse", new AccountCreationAbuse(options)));
    }

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      resultsList =
          resultsList.and(
              events
                  .apply(
                      "cfgtick processor",
                      ParDo.of(new CfgTickProcessor("customs-cfgtick", "category")))
                  .apply(new GlobalTriggers<Alert>(5)));
    }

    return resultsList.apply("flatten all output", Flatten.<Alert>pCollections());
  }

  private static void runCustoms(CustomsOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input =
        p.apply("input", Input.compositeInputAdapter(options, buildConfigurationTick(options)));
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
