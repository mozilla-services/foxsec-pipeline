package com.mozilla.secops.customs;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
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
import java.util.ArrayList;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.Duration;

/** Implements various analysis heuristics on {@link com.mozilla.secops.parser.FxaAuth} streams */
public class Customs implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String CATEGORY_SOURCE_LOGIN_FAILURE = "source_login_failure";
  public static final String CATEGORY_SOURCE_LOGIN_FAILURE_DIST =
      "source_login_failure_distributed";
  public static final String CATEGORY_ACCOUNT_CREATION_ABUSE = "account_creation_abuse";
  public static final String CATEGORY_ACCOUNT_CREATION_ABUSE_DIST =
      "account_creation_abuse_distributed";
  public static final String CATEGORY_VELOCITY = "velocity";
  public static final String CATEGORY_VELOCITY_MONITOR_ONLY = "velocity_monitor_only";
  public static final String CATEGORY_PASSWORD_RESET_ABUSE = "password_reset_abuse";

  /** Used by keyEvents */
  private enum KeyType {
    SOURCEADDRESS, // Key by source address
    EMAIL, // Key by email address
    DOMAIN // Key by domain extracted from email address
  }

  private static class CollectionInfo {
    public PCollection<KV<String, Event>> sourceKey;
    public PCollection<KV<String, Event>> emailKey;
    public PCollection<KV<String, Event>> domainKey;
  }

  /**
   * Return an array of EventSummary values that indicate which events should be stored during
   * feature extraction and passed through the prefilter.
   *
   * <p>Any EventSummary values returned here will indicate that an event of that type should be
   * stored during feature extraction. This is required if the underlying analysis transform needs
   * to operate on the events themselves.
   *
   * <p>If a particular event type is not returned here, it will not be available to any analysis
   * transforms.
   *
   * @return ArrayList
   */
  public static ArrayList<FxaAuth.EventSummary> featureSummaryRegistration() {
    ArrayList<FxaAuth.EventSummary> ret = new ArrayList<>();
    ret.add(FxaAuth.EventSummary.ACCOUNT_CREATE_SUCCESS);
    ret.add(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_SUCCESS);
    ret.add(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_FAILURE);
    ret.add(FxaAuth.EventSummary.LOGIN_FAILURE);
    ret.add(FxaAuth.EventSummary.LOGIN_SUCCESS);
    return ret;
  }

  /**
   * Summarizes various events processed by Customs pipeline
   *
   * <p>For each event the summary transform is aware of, an alert will be emitted every 15 minutes
   * that simply indicates the number of those events seen in the previous 15 minutes.
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

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return "Summarizes various event counts over 15 minute period.";
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      return col.apply(
              "summary identify event type",
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
                      }
                    }
                  }))
          .apply(
              "summary fixed windows",
              Window.<String>into(FixedWindows.of(Duration.standardMinutes(15))))
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
                      alert.setSubcategory("summary");
                      // We are using undefined keys here, so use custom metadata.
                      alert.addCustomMetadata(v.getKey(), v.getValue().toString());
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

    @Description(
        "Enable account creation abuse detector; CustomsAccountCreation, CustomsAccountCreationDist")
    @Default.Boolean(false)
    Boolean getEnableAccountCreationAbuseDetector();

    void setEnableAccountCreationAbuseDetector(Boolean value);

    @Description("Enable escalation of account creation alerts; CustomsAccountCreation")
    @Default.Boolean(false)
    Boolean getEscalateAccountCreation();

    void setEscalateAccountCreation(Boolean value);

    @Description(
        "Enable escalation of distributed account creation alerts; CustomsAccountCreationDist")
    @Default.Boolean(false)
    Boolean getEscalateAccountCreationDistributed();

    void setEscalateAccountCreationDistributed(Boolean value);

    @Description("Account creation alert threshold for CustomsAccountCreation")
    @Default.Integer(20)
    Integer getAccountCreationThreshold();

    void setAccountCreationThreshold(Integer value);

    @Description("Account creation alert threshold for CustomsAccountCreationDist")
    @Default.Integer(15)
    Integer getAccountCreationDistributedThreshold();

    void setAccountCreationDistributedThreshold(Integer value);

    @Description("Account creation string distance upper ratio for CustomsAccountCreationDist")
    @Default.Double(0.35)
    Double getAccountCreationDistributedDistanceRatio();

    void setAccountCreationDistributedDistanceRatio(Double value);

    @Description(
        "For CustomsAccountCreation, optionally use supplied suppress_recovery for violations; seconds")
    Integer getAccountCreationSuppressRecovery();

    void setAccountCreationSuppressRecovery(Integer value);

    @Description("Enable source login failure detector; SourceLoginFailure, SourceLoginFailureDist")
    @Default.Boolean(false)
    Boolean getEnableSourceLoginFailureDetector();

    void setEnableSourceLoginFailureDetector(Boolean value);

    @Description("Enable escalation of source login failure alerts; SourceLoginFailure")
    @Default.Boolean(false)
    Boolean getEscalateSourceLoginFailure();

    void setEscalateSourceLoginFailure(Boolean value);

    @Description(
        "Enable escalation of distributed source login failure alerts; SourceLoginFailureDist")
    @Default.Boolean(false)
    Boolean getEscalateSourceLoginFailureDistributed();

    void setEscalateSourceLoginFailureDistributed(Boolean value);

    @Description("Login failure alert threshold for SourceLoginFailure")
    @Default.Integer(30)
    Integer getSourceLoginFailureThreshold();

    void setSourceLoginFailureThreshold(Integer value);

    @Description(
        "Distinct addresses failing login for same account to trigger alert for SourceLoginFailureDist")
    @Default.Integer(10)
    Integer getSourceLoginFailureDistributedThreshold();

    void setSourceLoginFailureDistributedThreshold(Integer value);

    @Description("Enable customs summary analysis; CustomsSummary")
    @Default.Boolean(false)
    Boolean getEnableSummaryAnalysis();

    void setEnableSummaryAnalysis(Boolean value);

    @Description("Enable velocity analysis; CustomsVelocity")
    @Default.Boolean(false)
    Boolean getEnableVelocityDetector();

    void setEnableVelocityDetector(Boolean value);

    @Description("Enable escalation of velocity alerts; CustomsVelocity")
    @Default.Boolean(false)
    Boolean getEscalateVelocity();

    void setEscalateVelocity(Boolean value);

    @Description("Maximum km/h for velocity analysis")
    @Default.Integer(800)
    Integer getMaximumKilometersPerHour();

    void setMaximumKilometersPerHour(Integer value);

    @Description("Minimum distance that must be travelled (km) to create velocity alert")
    Double getMinimumDistanceForAlert();

    void setMinimumDistanceForAlert(Double value);

    @Description("Enable velocity analysis; CustomsVelocityMonitorOnly")
    @Default.Boolean(false)
    Boolean getEnableVelocityDetectorMonitorOnly();

    void setEnableVelocityDetectorMonitorOnly(Boolean value);

    @Description("Maximum km/h for velocity analysis; CustomsVelocityMonitorOnly")
    @Default.Integer(800)
    Integer getMaximumKilometersPerHourMonitorOnly();

    void setMaximumKilometersPerHourMonitorOnly(Integer value);

    @Description(
        "Minimum distance that must be travelled (km) to create velocity alert; CustomsVelocityMonitorOnly")
    Double getMinimumDistanceForAlertMonitorOnly();

    void setMinimumDistanceForAlertMonitorOnly(Double value);

    @Description("Enable password reset abuse analysis; CustomsPasswordResetAbuse")
    @Default.Boolean(false)
    Boolean getEnablePasswordResetAbuseDetector();

    void setEnablePasswordResetAbuseDetector(Boolean value);

    @Description("Enable escalation of password reset abuse alerts; CustomsPasswordResetAbuse")
    @Default.Boolean(false)
    Boolean getEscalatePasswordResetAbuse();

    void setEscalatePasswordResetAbuse(Boolean value);

    @Description("Password reset alert threshold for CustomsPasswordResetAbuse")
    @Default.Integer(5)
    Integer getPasswordResetAbuseThreshold();

    void setPasswordResetAbuseThreshold(Integer value);

    @Description("Pubsub topic for CustomsAlert notifications; Pubsub topic")
    String getCustomsNotificationTopic();

    void setCustomsNotificationTopic(String value);
  }

  /**
   * Build a configuration tick for Customs given pipeline options
   *
   * @param options Pipeline options
   * @return String
   * @throws IOException IOException
   */
  public static String buildConfigurationTick(CustomsOptions options) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    if (options.getEnableAccountCreationAbuseDetector()) {
      b.withTransformDoc(new CustomsAccountCreation(options));

      b.withTransformDoc(new CustomsAccountCreationDist(options));
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

  private static PCollection<KV<String, Event>> keyEvents(
      PCollection<Event> input, KeyType kt, String stepName) {
    return input.apply(
        stepName,
        ParDo.of(
            new DoFn<Event, KV<String, Event>>() {
              private static final long serialVersionUID = 1L;

              @ProcessElement
              public void processElement(ProcessContext c) {
                Event e = c.element();
                String s;
                switch (kt) {
                  case SOURCEADDRESS:
                    s = CustomsUtil.authGetSourceAddress(e);
                    break;
                  case EMAIL:
                    s = CustomsUtil.authGetEmail(e);
                    break;
                  case DOMAIN:
                    s = CustomsUtil.authGetEmail(e);
                    if (s == null) {
                      return;
                    }
                    String[] parts = s.split("@");
                    if (parts.length != 2) {
                      return;
                    }
                    s = parts[1];
                    break;
                  default:
                    throw new RuntimeException("unhandled key type");
                }
                if (s == null) {
                  return;
                }
                c.output(KV.of(s, e));
              }
            }));
  }

  private static PCollectionList<Alert> fixedTenMinutes(
      PCollectionList<Alert> ret, CollectionInfo ci, CustomsOptions options) {
    PCollection<KV<String, CustomsFeatures>> sourceWindowed = null;
    PCollection<KV<String, CustomsFeatures>> emailWindowed = null;
    PCollection<KV<String, CustomsFeatures>> domainWindowed = null;

    if (options.getEnablePasswordResetAbuseDetector()
        || options.getEnableSourceLoginFailureDetector()
        || options.getEnableAccountCreationAbuseDetector()) {
      sourceWindowed =
          ci.sourceKey
              .apply(
                  "fixed ten source address",
                  Window.<KV<String, Event>>into(FixedWindows.of(Duration.standardMinutes(10)))
                      .triggering(
                          AfterWatermark.pastEndOfWindow()
                              .withEarlyFirings(
                                  AfterProcessingTime.pastFirstElementInPane()
                                      .plusDelayOf(Duration.standardSeconds(30))))
                      .withAllowedLateness(Duration.ZERO)
                      .accumulatingFiredPanes())
              .apply("fixed ten source address features", new CustomsFeaturesCombiner());
    }
    if (options.getEnableSourceLoginFailureDetector()) {
      emailWindowed =
          ci.emailKey
              .apply(
                  "fixed ten email",
                  Window.<KV<String, Event>>into(FixedWindows.of(Duration.standardMinutes(10)))
                      .triggering(
                          AfterWatermark.pastEndOfWindow()
                              .withEarlyFirings(
                                  AfterProcessingTime.pastFirstElementInPane()
                                      .plusDelayOf(Duration.standardSeconds(30))))
                      .withAllowedLateness(Duration.ZERO)
                      .accumulatingFiredPanes())
              .apply("fixed ten email features", new CustomsFeaturesCombiner());
    }
    if (options.getEnableAccountCreationAbuseDetector()) {
      domainWindowed =
          ci.domainKey
              .apply(
                  "fixed ten domain",
                  Window.<KV<String, Event>>into(FixedWindows.of(Duration.standardMinutes(10)))
                      .triggering(
                          AfterWatermark.pastEndOfWindow()
                              .withEarlyFirings(
                                  AfterProcessingTime.pastFirstElementInPane()
                                      .plusDelayOf(Duration.standardSeconds(30))))
                      .withAllowedLateness(Duration.ZERO)
                      .accumulatingFiredPanes())
              .apply("fixed ten domain features", new CustomsFeaturesCombiner());
    }

    if (options.getEnablePasswordResetAbuseDetector()) {
      ret =
          ret.and(
              sourceWindowed.apply("password reset abuse", new CustomsPasswordResetAbuse(options)));
    }
    if (options.getEnableSourceLoginFailureDetector()) {
      ret =
          ret.and(sourceWindowed.apply("source login failure", new SourceLoginFailure(options)))
              .and(
                  emailWindowed.apply(
                      "source login failure distributed", new SourceLoginFailureDist(options)));
    }
    if (options.getEnableAccountCreationAbuseDetector()) {
      ret =
          ret.and(sourceWindowed.apply("account creation", new CustomsAccountCreation(options)))
              .and(
                  domainWindowed.apply(
                      "account creation distributed", new CustomsAccountCreationDist(options)));
    }

    return ret;
  }

  /**
   * Analysis entry point for Customs pipeline
   *
   * @param p Pipeline
   * @param input Input data
   * @param options CustomsOptions
   * @return {@link PCollection} containing {@link Alert} objects
   * @throws IOException IOException
   */
  public static PCollection<Alert> executePipeline(
      Pipeline p, PCollection<String> input, CustomsOptions options) throws IOException {
    PCollection<Event> events =
        input
            .apply(
                "parse",
                ParDo.of(new ParserDoFn().withConfiguration(ParserCfg.fromInputOptions(options))))
            .apply("prefilter", new CustomsPreFilter());

    PCollectionList<Alert> resultsList = PCollectionList.empty(p);
    CollectionInfo ci = new CollectionInfo();

    if (options.getEnablePasswordResetAbuseDetector()
        || options.getEnableSourceLoginFailureDetector()
        || options.getEnableAccountCreationAbuseDetector()) {
      ci.sourceKey = keyEvents(events, KeyType.SOURCEADDRESS, "source address key");
    }
    if (options.getEnableSourceLoginFailureDetector()) {
      ci.emailKey = keyEvents(events, KeyType.EMAIL, "email key");
    }
    if (options.getEnableAccountCreationAbuseDetector()) {
      ci.domainKey = keyEvents(events, KeyType.DOMAIN, "domain key");
    }

    resultsList = fixedTenMinutes(resultsList, ci, options);

    if (options.getEnableVelocityDetector()) {
      resultsList =
          resultsList.and(events.apply("location velocity", new CustomsVelocity(options)));
    }

    if (options.getEnableSummaryAnalysis()) {
      resultsList = resultsList.and(events.apply("summary", new CustomsSummary(options)));
    }

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      resultsList =
          resultsList.and(
              events
                  .apply("cfgtick processor", ParDo.of(new CfgTickProcessor("customs-cfgtick")))
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
        alerts
            .apply("alert formatter", ParDo.of(new AlertFormatter(options)))
            .apply("alert conversion", MapElements.via(new AlertFormatter.AlertToString()));
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
   * @throws IOException IOException
   */
  public static void main(String[] args) throws IOException {
    PipelineOptionsFactory.register(CustomsOptions.class);
    CustomsOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(CustomsOptions.class);
    runCustoms(options);
  }
}
