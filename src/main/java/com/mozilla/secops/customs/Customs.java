package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
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
import org.apache.beam.sdk.transforms.Count;
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

  public static final String CATEGORY_SOURCE_LOGIN_FAILURE = "source_login_failure";
  public static final String CATEGORY_SOURCE_LOGIN_FAILURE_DIST =
      "source_login_failure_distributed";
  public static final String CATEGORY_ACCOUNT_CREATION_ABUSE = "account_creation_abuse";
  public static final String CATEGORY_ACCOUNT_CREATION_ABUSE_DIST =
      "account_creation_abuse_distributed";
  public static final String CATEGORY_VELOCITY = "velocity";
  public static final String CATEGORY_PASSWORD_RESET_ABUSE = "password_reset_abuse";

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
   * Summarizes various events processed by Customs pipeline
   *
   * <p>Emits an alert message which is a summary of events processed by the Customs pipeline over a
   * fixed 15 minute interval.
   */
  public static class CustomsSummary extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final String monitoredResource;

    /**
     * Initialize new CustomsSummary
     *
     * @param options CustomsOptions
     */
    public CustomsSummary(CustomsOptions options) {
      monitoredResource = options.getMonitoredResourceIndicator();
    }

    public String getTransformDoc() {
      return "Summarizes various event counts over 15 minute period in an alert message.";
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      return col.apply(
              "summary element identification",
              ParDo.of(
                  new DoFn<Event, String>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Event e = c.element();

                      FxaAuth.EventSummary s = CustomsUtil.authGetEventSummary(e);
                      if (s == null) {
                        // If we couldn't extract a summary from the event, just ignore it.
                        return;
                      }
                      switch (s) {
                        case LOGIN_FAILURE:
                          c.output("login_failure");
                          break;
                        case ACCOUNT_CREATE_SUCCESS:
                          c.output("account_create_success");
                          break;
                        case LOGIN_SUCCESS:
                          c.output("login_success");
                          break;
                        default:
                          return;
                      }
                    }
                  }))
          .apply(
              "summary fixed windows",
              Window.<String>into(FixedWindows.of(Duration.standardSeconds(900))))
          .apply("summary element count", Count.perElement())
          .apply(
              "summary analysis",
              ParDo.of(
                  new DoFn<KV<String, Long>, Alert>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      KV<String, Long> v = c.element();

                      Alert alert = new Alert();
                      alert.setCategory("customs");
                      alert.addMetadata("customs_category", "summary");
                      alert.addMetadata(v.getKey(), v.getValue().toString());
                      alert.setSummary(
                          String.format(
                              "%s summary for period, %s %d",
                              monitoredResource, v.getKey(), v.getValue()));
                      c.output(alert);
                    }
                  }))
          .apply("summary global windows", new GlobalTriggers<Alert>(5));
    }
  }

  /** Runtime options for {@link Customs} pipeline. */
  public interface CustomsOptions extends PipelineOptions, IOOptions {
    @Description("Use memcached state; hostname of memcached server")
    String getMemcachedHost();

    void setMemcachedHost(String value);

    @Description("Use memcached state; port of memcached server")
    @Default.Integer(11211)
    Integer getMemcachedPort();

    void setMemcachedPort(Integer value);

    @Description("Use Datastore state; namespace for entities")
    String getDatastoreNamespace();

    void setDatastoreNamespace(String value);

    @Description("Enable account creation abuse detector")
    @Default.Boolean(false)
    Boolean getEnableAccountCreationAbuseDetector();

    void setEnableAccountCreationAbuseDetector(Boolean value);

    @Description("Enable escalation of account creation alerts")
    @Default.Boolean(false)
    Boolean getEscalateAccountCreation();

    void setEscalateAccountCreation(Boolean value);

    @Description("Enable escalation of distributed account creation alerts")
    @Default.Boolean(false)
    Boolean getEscalateAccountCreationDistributed();

    void setEscalateAccountCreationDistributed(Boolean value);

    @Description("Account creation limit for session abuse analysis")
    @Default.Integer(20)
    Integer getAccountCreationSessionLimit();

    void setAccountCreationSessionLimit(Integer value);

    @Description("Account creation threshold for string distance analysis")
    @Default.Integer(15)
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

    @Description("Enable source login failure detector")
    @Default.Boolean(false)
    Boolean getEnableSourceLoginFailureDetector();

    void setEnableSourceLoginFailureDetector(Boolean value);

    @Description("Enable escalation of source login failure alerts")
    @Default.Boolean(false)
    Boolean getEscalateSourceLoginFailure();

    void setEscalateSourceLoginFailure(Boolean value);

    @Description("Enable escalation of distributed source login failure alerts")
    @Default.Boolean(false)
    Boolean getEscalateSourceLoginFailureDistributed();

    void setEscalateSourceLoginFailureDistributed(Boolean value);

    @Description("Login failures per source-address in 5 minute window to trigger alert")
    @Default.Integer(30)
    Integer getSourceLoginFailureThreshold();

    void setSourceLoginFailureThreshold(Integer value);

    @Description(
        "Distinct addresses failing login for same account in 10 minute window to trigger alert")
    @Default.Integer(10)
    Integer getSourceLoginFailureDistributedThreshold();

    void setSourceLoginFailureDistributedThreshold(Integer value);

    @Description("Enable customs summary analysis")
    @Default.Boolean(false)
    Boolean getEnableSummaryAnalysis();

    void setEnableSummaryAnalysis(Boolean value);

    @Description("Enable velocity analysis")
    @Default.Boolean(false)
    Boolean getEnableVelocityDetector();

    void setEnableVelocityDetector(Boolean value);

    @Description("Maximum km/h for velocity analysis")
    @Default.Integer(800)
    Integer getMaximumKilometersPerHour();

    void setMaximumKilometersPerHour(Integer value);

    @Description("Enable password reset abuse analysis")
    @Default.Boolean(false)
    Boolean getEnablePasswordResetAbuseDetector();

    void setEnablePasswordResetAbuseDetector(Boolean value);

    @Description("Enable escalation of password reset abuse alerts")
    @Default.Boolean(false)
    Boolean getEscalatePasswordResetAbuse();

    void setEscalatePasswordResetAbuse(Boolean value);

    @Description(
        "Successful password reset requests per-IP for different accounts in window to trigger alert")
    @Default.Integer(5)
    Integer getPasswordResetAbuseWindowThresholdPerIp();

    void setPasswordResetAbuseWindowThresholdPerIp(Integer value);

    @Description("Pubsub topic for CustomsAlert notifications; Pubsub topic")
    String getCustomsNotificationTopic();

    void setCustomsNotificationTopic(String value);
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

    if (options.getEnableSourceLoginFailureDetector()) {
      b.withTransformDoc(new SourceLoginFailure(options));
      b.withTransformDoc(new SourceLoginFailureDist(options));
    }

    if (options.getEnableVelocityDetector()) {
      b.withTransformDoc(new CustomsVelocity(options));
    }

    if (options.getEnablePasswordResetAbuseDetector()) {
      b.withTransformDoc(new CustomsPasswordResetAbuse(options));
    }

    if (options.getEnableSummaryAnalysis()) {
      b.withTransformDoc(new CustomsSummary(options));
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
    if (options.getEnableSourceLoginFailureDetector()) {
      resultsList =
          resultsList
              .and(events.apply("source login failure", new SourceLoginFailure(options)))
              .and(
                  events.apply(
                      "source login failure distributed", new SourceLoginFailureDist(options)));
    }
    if (options.getEnableVelocityDetector()) {
      resultsList =
          resultsList.and(events.apply("location velocity", new CustomsVelocity(options)));
    }
    if (options.getEnablePasswordResetAbuseDetector()) {
      resultsList =
          resultsList.and(
              events.apply("password reset abuse", new CustomsPasswordResetAbuse(options)));
    }
    if (options.getEnableSummaryAnalysis()) {
      resultsList = resultsList.and(events.apply("summary", new CustomsSummary(options)));
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

    PCollection<String> fmt =
        alerts.apply("alert formatter", ParDo.of(new AlertFormatter(options)));
    fmt.apply("output", OutputOptions.compositeOutput(options));

    // If the customs notification topic is set, wire the alerts up to this output transform
    // as well.
    if (options.getCustomsNotificationTopic() != null) {
      fmt.apply("customs notification", new CustomsNotification(options));
    }

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
