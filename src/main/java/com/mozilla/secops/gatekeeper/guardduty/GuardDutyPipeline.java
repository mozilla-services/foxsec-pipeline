package com.mozilla.secops.gatekeeper.guardduty;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.parser.*;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.*;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/**
 * {@link GuardDutyPipeline} describes and implements a Beam pipeline for analysis of AWS GuardDuty
 * Findings, which come with a wrapper AWS CloudWatch Event
 */
public class GuardDutyPipeline implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) {
    PipelineOptionsFactory.register(GuardDutyOptions.class);

    GuardDutyOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(GuardDutyOptions.class);

    Pipeline p = Pipeline.create(options);

    PCollection<Event> events =
        p.apply("input", new CompositeInput(options))
            .apply("parse", new GuardDutyParser.Parse(options));

    PCollection<KV<String, Event>> byFindingType =
        events.apply("group by type", new GuardDutyTransforms.ByType());

    byFindingType.apply(new GuardDutyTransforms.PrintKeys());

    p.run().waitUntilFinish();
  }
}
