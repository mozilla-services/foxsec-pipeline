package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * {@link GatekeeperPipeline} describes and implements a Beam pipeline for analysis of AWS GuardDuty
 * and GCP Event Threat Detection Findings
 */
public class GatekeeperPipeline implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for {@link GatekeeperPipeline} . */
  public interface GatekeeperOptions extends ETDTransforms.Options, GuardDutyTransforms.Options {
    @Description("Enable ETD")
    @Default.Boolean(true)
    Boolean getEnableETD();

    void setEnableETD(Boolean value);

    @Description("Enable GD")
    @Default.Boolean(true)
    Boolean getEnableGD();

    void setEnableGD(Boolean value);
  }

  /**
   * Execute Gatekeeper pipeline
   *
   * @param p Pipeline
   * @param input Input collection
   * @param options GatekeeperOptions
   * @return Collection of Alert objects
   */
  public static PCollection<Alert> executePipeline(
      Pipeline p, PCollection<String> input, GatekeeperOptions options) {

    PCollection<Event> events =
        input
            .apply("parse input", new GatekeeperParser.Parse(options))
            .apply("window input", new GlobalTriggers<Event>(60));

    PCollectionList<Alert> alertList = PCollectionList.empty(input.getPipeline());

    if (options.getEnableGD()) {
      alertList =
          alertList.and(
              events
                  .apply("extract gd findings", new GuardDutyTransforms.ExtractFindings(options))
                  .apply("generate gd alerts", new GuardDutyTransforms.GenerateGDAlerts(options))
                  .apply("suppress gd alerts", new GuardDutyTransforms.SuppressAlerts(options)));
    }

    if (options.getEnableETD()) {
      alertList =
          alertList.and(
              events
                  .apply("extract etd findings", new ETDTransforms.ExtractFindings(options))
                  .apply("generate etd alerts", new ETDTransforms.GenerateETDAlerts(options))
                  .apply("suppress etd alerts", new ETDTransforms.SuppressAlerts(options)));
    }

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      alertList =
          alertList.and(
              events
                  .apply(
                      "cfgtick processor",
                      ParDo.of(new CfgTickProcessor("gatekeeper-cfgtick", "category")))
                  .apply(new GlobalTriggers<Alert>(60)));
    }

    return alertList.apply("flatten output", Flatten.<Alert>pCollections());
  }

  /**
   * Build a configuration tick for Gatekeeper given pipeline options
   *
   * @param options Pipeline options
   * @return String
   */
  public static String buildConfigurationTick(GatekeeperOptions options) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    if (options.getEnableGD()) {
      b.withTransformDoc(new GuardDutyTransforms.GenerateGDAlerts(options));
    }
    if (options.getEnableETD()) {
      b.withTransformDoc(new ETDTransforms.GenerateETDAlerts(options));
    }

    return b.build();
  }

  private static void runGatekeeper(GatekeeperOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input;
    try {
      input =
          p.apply("input", Input.compositeInputAdapter(options, buildConfigurationTick(options)));
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }

    executePipeline(p, input, options)
        .apply("output format", ParDo.of(new AlertFormatter(options)))
        .apply("output convert", MapElements.via(new AlertFormatter.AlertToString()))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) throws Exception {
    PipelineOptionsFactory.register(GatekeeperOptions.class);

    GatekeeperOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(GatekeeperOptions.class);

    runGatekeeper(options);
  }
}
