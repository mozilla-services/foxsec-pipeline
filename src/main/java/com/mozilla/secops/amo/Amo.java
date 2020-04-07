package com.mozilla.secops.amo;

import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/** Various heuristics for AMO analysis */
public class Amo implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Execute AMO pipeline
   *
   * @param p Pipeline
   * @param input Input collection
   * @param options AmoOptions
   * @return Collection of Alert objects
   * @throws IOException IOException
   */
  public static PCollection<Alert> executePipeline(
      Pipeline p, PCollection<String> input, AmoOptions options) throws IOException {
    // A valid iprepd configuration is required here, as values are pulled from iprepd in some of
    // the pipeline transforms
    if ((options.getInputIprepd() == null)) {
      throw new RuntimeException("iprepd pipeline configuration options are required");
    }

    ParserCfg cfg = ParserCfg.fromInputOptions(options);

    EventFilter filter = new EventFilter().passConfigurationTicks();
    filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.AMODOCKER));

    PCollection<Event> parsed =
        input.apply(
            ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)));

    PCollectionList<Alert> resultsList = PCollectionList.empty(p);

    resultsList =
        resultsList.and(
            parsed.apply(
                "fxa account abuse new version",
                new FxaAccountAbuseNewVersion(
                    options.getMonitoredResourceIndicator(),
                    options.getAccountMatchBanOnLogin(),
                    options.getBanPatternSuppressRecovery(),
                    options.getInputIprepd(),
                    options.getProject())));
    resultsList =
        resultsList.and(
            parsed.apply(
                "amo report restriction",
                new ReportRestriction(options.getMonitoredResourceIndicator())));

    resultsList =
        resultsList.and(
            parsed.apply(
                "fxa account abuse alias",
                new FxaAccountAbuseAlias(
                    options.getMonitoredResourceIndicator(),
                    options.getAliasAbuseSuppressRecovery(),
                    options.getAliasAbuseMaxAliases())));

    resultsList =
        resultsList.and(
            parsed.apply(
                "addon abuse match",
                new AddonMatcher(
                    options.getMonitoredResourceIndicator(),
                    options.getAddonMatchSuppressRecovery(),
                    options.getAddonMatchCriteria())));

    resultsList =
        resultsList.and(
            parsed.apply(
                "addon multi match",
                new AddonMultiMatch(
                    options.getMonitoredResourceIndicator(),
                    options.getAddonMultiMatchSuppressRecovery(),
                    options.getAddonMultiMatchAlertOn())));

    resultsList =
        resultsList.and(
            parsed.apply(
                "addon multi submit",
                new AddonMultiSubmit(
                    options.getMonitoredResourceIndicator(),
                    options.getAddonMultiSubmitSuppressRecovery(),
                    options.getAddonMultiSubmitAlertOn())));

    resultsList =
        resultsList.and(
            parsed.apply(
                "addon multi ip login",
                new AddonMultiIpLogin(
                    options.getMonitoredResourceIndicator(),
                    options.getAddonMultiIpLoginSuppressRecovery(),
                    options.getAddonMultiIpLoginAlertOn(),
                    options.getAddonMultiIpLoginAlertOnIp(),
                    options.getAddonMultiIpLoginAlertExceptions(),
                    options.getAddonMultiIpLoginAggressiveMatcher())));

    resultsList =
        resultsList.and(
            parsed.apply(
                "addon cloud submission",
                new AddonCloudSubmission(options.getMonitoredResourceIndicator())));

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      resultsList =
          resultsList.and(
              parsed
                  .apply("cfgtick processor", ParDo.of(new CfgTickProcessor("amo-cfgtick")))
                  .apply(new GlobalTriggers<Alert>(5)));
    }

    return resultsList.apply("amo flatten output", Flatten.<Alert>pCollections());
  }

  /** Runtime options for {@link Amo} pipeline. */
  public interface AmoOptions extends PipelineOptions, IOOptions {
    @Description("On login if account matches regex, generate alert regardless of reputation")
    String[] getAccountMatchBanOnLogin();

    void setAccountMatchBanOnLogin(String[] value);

    @Description(
        "For login ban on regex match, optionally use supplied suppress_recovery for violations; seconds")
    Integer getBanPatternSuppressRecovery();

    void setBanPatternSuppressRecovery(Integer value);

    @Description(
        "For account alias abuse, number of aliases seen used within one session to generate an alert")
    @Default.Integer(5)
    Integer getAliasAbuseMaxAliases();

    void setAliasAbuseMaxAliases(Integer value);

    @Description(
        "For account alias abuse, optionally use supplied suppress_recovery for violations; seconds")
    Integer getAliasAbuseSuppressRecovery();

    void setAliasAbuseSuppressRecovery(Integer value);

    @Description(
        "Match criteria for abusive addon matcher (multiple allowed); <fileregex>:<minbytes>:<maxbytes>")
    String[] getAddonMatchCriteria();

    void setAddonMatchCriteria(String[] value);

    @Description(
        "For abusive addon match, optionally use supplied suppress_recovery for violations; seconds")
    Integer getAddonMatchSuppressRecovery();

    void setAddonMatchSuppressRecovery(Integer value);

    @Description(
        "Generate multi match alert if uploads exceed this number in a given window with same file name")
    @Default.Integer(5)
    Integer getAddonMultiMatchAlertOn();

    void setAddonMultiMatchAlertOn(Integer value);

    @Description(
        "For abusive addon multi match, optionally use supplied suppress_recovery for violations; seconds")
    Integer getAddonMultiMatchSuppressRecovery();

    void setAddonMultiMatchSuppressRecovery(Integer value);

    @Description("For abusive addon multi submit, alert if submission count exceeds value")
    @Default.Integer(10)
    Integer getAddonMultiSubmitAlertOn();

    void setAddonMultiSubmitAlertOn(Integer value);

    @Description(
        "For abusive addon multi submit, optionally use supplied suppress_recovery for violations; seconds")
    Integer getAddonMultiSubmitSuppressRecovery();

    void setAddonMultiSubmitSuppressRecovery(Integer value);

    @Description("Number of countries seen within window to generate multi IP login alert")
    @Default.Integer(2)
    Integer getAddonMultiIpLoginAlertOn();

    void setAddonMultiIpLoginAlertOn(Integer value);

    @Description(
        "For multi IP login, when country count exceeded, specify distinct IP count that must also be met")
    @Default.Integer(10)
    Integer getAddonMultiIpLoginAlertOnIp();

    void setAddonMultiIpLoginAlertOnIp(Integer value);

    @Description(
        "Exempt accounts matching regex from IP country login analysis (multiple allowed); regex")
    String[] getAddonMultiIpLoginAlertExceptions();

    void setAddonMultiIpLoginAlertExceptions(String[] value);

    @Description(
        "If account matches regex, submit violation on any multi-country access regardless of IP "
            + "count (multiple allowed); regex")
    String[] getAddonMultiIpLoginAggressiveMatcher();

    void setAddonMultiIpLoginAggressiveMatcher(String[] value);

    @Description(
        "For abusive addon multi IP login, optionally use supplied suppress_recovery for violations; seconds")
    Integer getAddonMultiIpLoginSuppressRecovery();

    void setAddonMultiIpLoginSuppressRecovery(Integer value);
  }

  /**
   * Build a configuration tick for Amo given pipeline options
   *
   * @param options Pipeline options
   * @return String
   * @throws IOException IOException
   */
  public static String buildConfigurationTick(AmoOptions options) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    b.withTransformDoc(
        new FxaAccountAbuseNewVersion(
            options.getMonitoredResourceIndicator(),
            options.getAccountMatchBanOnLogin(),
            options.getBanPatternSuppressRecovery(),
            options.getInputIprepd(),
            options.getProject()));

    b.withTransformDoc(new ReportRestriction(options.getMonitoredResourceIndicator()));

    b.withTransformDoc(
        new FxaAccountAbuseAlias(
            options.getMonitoredResourceIndicator(),
            options.getAliasAbuseSuppressRecovery(),
            options.getAliasAbuseMaxAliases()));

    b.withTransformDoc(
        new AddonMatcher(
            options.getMonitoredResourceIndicator(),
            options.getAddonMatchSuppressRecovery(),
            options.getAddonMatchCriteria()));

    b.withTransformDoc(
        new AddonMultiMatch(
            options.getMonitoredResourceIndicator(),
            options.getAddonMultiMatchSuppressRecovery(),
            options.getAddonMultiMatchAlertOn()));

    b.withTransformDoc(
        new AddonMultiSubmit(
            options.getMonitoredResourceIndicator(),
            options.getAddonMultiSubmitSuppressRecovery(),
            options.getAddonMultiSubmitAlertOn()));

    b.withTransformDoc(
        new AddonMultiIpLogin(
            options.getMonitoredResourceIndicator(),
            options.getAddonMultiIpLoginSuppressRecovery(),
            options.getAddonMultiIpLoginAlertOn(),
            options.getAddonMultiIpLoginAlertOnIp(),
            options.getAddonMultiIpLoginAlertExceptions(),
            options.getAddonMultiIpLoginAggressiveMatcher()));

    b.withTransformDoc(new AddonCloudSubmission(options.getMonitoredResourceIndicator()));

    return b.build();
  }

  private static void runAmo(AmoOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input =
        p.apply("input", Input.compositeInputAdapter(options, buildConfigurationTick(options)));
    PCollection<Alert> alerts = executePipeline(p, input, options);

    alerts
        .apply("alert formatter", ParDo.of(new AlertFormatter(options)))
        .apply("alert conversion", MapElements.via(new AlertFormatter.AlertToString()))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   * @throws IOException IOException
   */
  public static void main(String[] args) throws IOException {
    PipelineOptionsFactory.register(AmoOptions.class);
    AmoOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(AmoOptions.class);
    runAmo(options);
  }
}
