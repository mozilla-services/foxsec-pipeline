package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * {@link GatekeeperPipeline} describes and implements a Beam pipeline for analysis of AWS GuardDuty
 * and GCP Event Threat Detection Findings
 */
public class GatekeeperPipeline implements Serializable {
  private static final long serialVersionUID = 1L;

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

    PCollection<Alert> gdAlerts =
        events
            .apply("extract gd findings", new GuardDutyTransforms.ExtractFindings(options))
            .apply("generate gd alerts", new GuardDutyTransforms.GenerateAlerts(options));

    PCollection<Alert> etdAlerts =
        events
            .apply("extract etd findings", new ETDTransforms.ExtractFindings(options))
            .apply("generate etd alerts", new ETDTransforms.GenerateAlerts(options));

    PCollection<Alert> alerts =
        PCollectionList.of(gdAlerts)
            .and(etdAlerts)
            .apply("combine alerts", Flatten.<Alert>pCollections());

    return alerts;
  }

  private static void runGatekeeper(GatekeeperOptions options) {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input = p.apply("read input", new CompositeInput(options));
    PCollection<Alert> alerts = executePipeline(p, input, options);

    alerts
        .apply("format output", ParDo.of(new AlertFormatter(options)))
        .apply("produce output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) {
    PipelineOptionsFactory.register(GatekeeperOptions.class);

    GatekeeperOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(GatekeeperOptions.class);

    runGatekeeper(options);
  }
}
