package com.mozilla.secops.customs;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.SecEvent;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Implements various rate limiting and analysis heuristics on {@link SecEvent} streams */
public class Customs implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Generic rate limiting detector driven by {@link CustomsCfgEntry} */
  public static class Detector extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private String detectorName;
    private final String monitoredResource;
    private final Long threshold;
    private final Long windowLength;
    private final Long windowSlides;
    private final Long suppressLength;
    private EventFilter filter;

    private Logger log;

    /**
     * Initialize detector
     *
     * @param detectorName Descriptive name for detector instance
     * @param cfg Configuration for detector
     */
    public Detector(String detectorName, CustomsCfgEntry cfg, String monitoredResource) {
      log = LoggerFactory.getLogger(Detector.class);
      log.info("initializing new detector, {}", detectorName);
      this.filter = null;
      this.detectorName = detectorName;
      this.threshold = cfg.getThreshold();
      this.windowLength = cfg.getSlidingWindowLength();
      this.windowSlides = cfg.getSlidingWindowSlides();
      this.suppressLength = cfg.getAlertSuppressionLength();
      this.monitoredResource = monitoredResource;
      try {
        this.filter = cfg.getEventFilterCfg().getEventFilter("default");
      } catch (IOException exc) {
        log.error("{} filter creation failed, {}", detectorName, exc.getMessage());
      }
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      return col.apply(
          RateLimitAnalyzer.getTransform(
              new RateLimitAnalyzer(detectorName, monitoredResource)
                  .setFilter(filter)
                  .setAlertCriteria(threshold, Alert.AlertSeverity.INFORMATIONAL)
                  .setAnalysisWindow(windowLength, windowSlides)
                  .setAlertSuppression(suppressLength)));
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
    @Description("path to customs configuration; resource path")
    @Default.String("/customs/customsdefault.json")
    String getConfigurationResourcePath();

    void setConfigurationResourcePath(String value);
  }

  private static void runCustoms(CustomsOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    CustomsCfg cfg = CustomsCfg.loadFromResource(options.getConfigurationResourcePath());

    ParserDoFn fn = new ParserDoFn();
    if (options.getMaxmindDbPath() != null) {
      fn = fn.withGeoIP(options.getMaxmindDbPath());
    }
    PCollection<Event> input =
        p.apply("input", options.getInputType().read(p, options)).apply("parse", ParDo.of(fn));

    PCollection<Alert> alerts = input.apply(new Detectors(cfg, options));

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
