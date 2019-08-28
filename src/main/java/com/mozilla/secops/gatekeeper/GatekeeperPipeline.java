package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
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

  /** Runtime options for {@link GatekeeperPipeline} . */
  public interface Options extends ETDTransforms.Options, GuardDutyTransforms.Options {}

  /**
   * Execute Gatekeeper pipeline
   *
   * @param p Pipeline
   * @param input Input collection
   * @param options GatekeeperOptions
   * @return Collection of Alert objects
   */
  public static PCollection<Alert> executePipeline(
      Pipeline p, PCollection<String> input, Options options) {

    PCollection<Event> events =
        input
            .apply("parse input", new GatekeeperParser.Parse(options))
            .apply("window input", new GlobalTriggers<Event>(60));

    PCollection<Alert> gdAlerts =
        events
            .apply("extract gd findings", new GuardDutyTransforms.ExtractFindings(options))
            .apply("generate gd alerts", new GuardDutyTransforms.GenerateAlerts(options))
            .apply("suppress gd alerts", new GuardDutyTransforms.SuppressAlerts(options));

    PCollection<Alert> etdAlerts =
        events
            .apply("extract etd findings", new ETDTransforms.ExtractFindings(options))
            .apply("generate etd alerts", new ETDTransforms.GenerateAlerts(options))
            .apply("suppress etd alerts", new ETDTransforms.SuppressAlerts(options));

    PCollection<Alert> alerts =
        PCollectionList.of(gdAlerts)
            .and(etdAlerts)
            .apply("combine alerts", Flatten.<Alert>pCollections());

    return alerts;
  }

  private static void runGatekeeper(Options options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input = p.apply("read input", Input.compositeInputAdapter(options, null));
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
  public static void main(String[] args) throws Exception {
    PipelineOptionsFactory.register(Options.class);

    Options options = PipelineOptionsFactory.fromArgs(args).withValidation().as(Options.class);

    runGatekeeper(options);
  }
}
