package com.mozilla.secops.customs;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertSuppressorCount;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
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
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
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
      return col.apply(new RateLimitAnalyzer(detectorName, cfg, monitoredResource));
    }
  }

  /** Analyze input stream for account creation abuse using client keyed sessions */
  public static class AccountCreationAbuse
      extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final String monitoredResource;
    private final String limitService;

    public AccountCreationAbuse(CustomsOptions options) {
      limitService = options.getAccountCreationServiceLimit();
      monitoredResource = options.getMonitoredResourceIndicator();
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      // Key and window for IP sessions with accumulating panes
      PCollection<KV<String, Event>> keyed =
          col.apply(
                  "key for sessions",
                  ParDo.of(
                      new DoFn<Event, KV<String, Event>>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c) {
                          Event e = c.element();

                          if (!(e.getPayloadType().equals(Payload.PayloadType.FXAAUTH))) {
                            return;
                          }
                          FxaAuth d = e.getPayload();
                          if (d == null) {
                            return;
                          }
                          String remoteAddress = d.getSourceAddress();
                          if (remoteAddress == null) {
                            return;
                          }

                          // Likely should be expanded to include other event types in
                          // relation to creation, but for now just look at creation
                          if (d.getEventSummary() == null) {
                            return;
                          }
                          if (!d.getEventSummary().equals(FxaAuth.EventSummary.ACCOUNT_CREATE)) {
                            return;
                          }

                          c.output(KV.of(remoteAddress, e));
                        }
                      }))
              .apply(
                  "window for sessions",
                  Window.<KV<String, Event>>into(
                          Sessions.withGapDuration(Duration.standardMinutes(30)))
                      .triggering(
                          Repeatedly.forever(
                              AfterWatermark.pastEndOfWindow()
                                  .withEarlyFirings(
                                      AfterProcessingTime.pastFirstElementInPane()
                                          .plusDelayOf(Duration.standardMinutes(5)))))
                      .withAllowedLateness(Duration.ZERO)
                      .accumulatingFiredPanes());

      // Group session keyed events
      PCollection<KV<String, Iterable<Event>>> grouped =
          keyed.apply(GroupByKey.<String, Event>create());

      // Analyze per key
      return grouped
          .apply(
              "analyze sessions",
              ParDo.of(
                  new DoFn<KV<String, Iterable<Event>>, KV<String, Alert>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      String remoteAddress = c.element().getKey();
                      Iterable<Event> events = c.element().getValue();

                      Boolean principalVariance = false;
                      int createCount = 0;

                      String seenPrincipal = null;
                      ArrayList<String> seenCreateAccounts = new ArrayList<>();
                      for (Event e : events) {
                        FxaAuth d = e.getPayload();
                        if (d == null) {
                          continue;
                        }
                        com.mozilla.secops.parser.models.fxaauth.FxaAuth authData =
                            d.getFxaAuthData();
                        if (authData == null) {
                          continue;
                        }
                        String email = authData.getEmail();
                        if (email == null) {
                          continue;
                        }

                        if (d.getEventSummary().equals(FxaAuth.EventSummary.ACCOUNT_CREATE)) {
                          String service = authData.getService();
                          if ((limitService == null)
                              || ((service != null) && (service.equals(limitService)))) {
                            seenCreateAccounts.add(email);
                            createCount++;
                          }
                        }

                        if (seenPrincipal == null) {
                          seenPrincipal = email;
                        } else {
                          if (!(seenPrincipal.equals(email))) {
                            principalVariance = true;
                          }
                        }
                      }

                      if ((createCount < 3) || (!principalVariance)) {
                        return;
                      }

                      Alert alert = new Alert();
                      alert.setCategory("customs");
                      alert.setNotifyMergeKey("account_creation_abuse");
                      alert.addMetadata("customs_category", "account_creation_abuse");
                      alert.addMetadata("sourceaddress", remoteAddress);
                      alert.addMetadata("count", Integer.toString(createCount));
                      alert.setSummary(
                          String.format(
                              "%s suspicious account creation, %s %d",
                              monitoredResource, remoteAddress, createCount));
                      String buf = "";
                      for (String s : seenCreateAccounts) {
                        if (buf.isEmpty()) {
                          buf = s;
                        } else {
                          buf += ", " + s;
                        }
                      }
                      alert.addMetadata("accounts", buf);
                      System.out.println(alert.toJSON());
                      c.output(KV.of(remoteAddress, alert));
                    }
                  }))
          .apply("global windows", new GlobalTriggers<KV<String, Alert>>(5))
          .apply(ParDo.of(new AlertSuppressorCount(1801L)));
    }
  }

  /** High level transform for invoking all detector instances given the customs configuration */
  public static class Detectors extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final CustomsCfg cfg;
    private final String monitoredResource;

    /**
     * Initialize new flattening detectors instance
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
      PCollection<Alert> ret = alerts.apply(Flatten.<Alert>pCollections());
      return ret;
    }
  }

  /** Runtime options for {@link Customs} pipeline. */
  public interface CustomsOptions extends PipelineOptions, InputOptions, OutputOptions {
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

    @Description("Limit account creation abuse detection to specified FxaAuth service indicator")
    String getAccountCreationServiceLimit();

    void setAccountCreationServiceLimit(String value);
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
      resultsList = resultsList.and(events.apply(new Detectors(cfg, options)));
    }
    if (options.getEnableAccountCreationAbuseDetector()) {
      resultsList = resultsList.and(events.apply(new AccountCreationAbuse(options)));
    }
    return resultsList.apply("flatten output", Flatten.<Alert>pCollections());
  }

  private static void runCustoms(CustomsOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input = p.apply("input", new CompositeInput(options));

    PCollection<Alert> alerts = executePipeline(p, input, options);

    alerts
        .apply(ParDo.of(new AlertFormatter(options)))
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
