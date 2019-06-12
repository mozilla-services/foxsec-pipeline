package com.mozilla.secops.cloudwatch;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.parser.*;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

/**
 * {@link CloudWatch} describes and implements a Beam pipeline for analysis of AWS CloudWatch
 * events, which may come from distinct source AWS services. CloudWatch from all services consist of
 * a set of common fields and a service specific "detail" JSON object
 */
public class CloudWatch implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for {@link CloudWatch} pipeline. */
  public interface CloudWatchOptions extends PipelineOptions, IOOptions {}

  /**
   * Composite transform to parse a {@link PCollection} containing events as strings and emit a
   * {@link PCollection} of {@link Event} objects.
   */
  public static class Parse extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    // add parser specific private fields here
    private ParserCfg cfg;

    /**
     * Static initializer for {@link Parse} transform
     *
     * @param options Pipeline options
     */
    public Parse(CloudWatchOptions options) {
      // set parser specific private option fields here
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> rawCloudWatchEventData) {
      EventFilter filter = new EventFilter();
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.CLOUDWATCH));

      PCollection<Event> parsed =
          rawCloudWatchEventData.apply(
              ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)));

      return parsed;
    }
  }

  /** transform to print out a {@link PCollection} containing strings */
  private static class PrintOutput extends PTransform<PCollection<String>, PDone> {
    private static final long serialVersionUID = 1L;

    @Override
    public PDone expand(PCollection<String> input) {
      input.apply(
          ParDo.of(
              new DoFn<String, Void>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  System.out.println(c.element());
                }
              }));
      return PDone.in(input.getPipeline());
    }
  }

  private static void runCloudWatch(CloudWatchOptions options) {
    Pipeline p = Pipeline.create(options);

    PCollection<Event> events =
        p.apply("input", new CompositeInput(options)).apply("parse", new Parse(options));

    PCollection<String> regions = events.apply(new ExtractRegions());

    regions.apply(new PrintOutput());

    p.run().waitUntilFinish();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) {
    PipelineOptionsFactory.register(CloudWatchOptions.class);
    CloudWatchOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(CloudWatchOptions.class);
    runCloudWatch(options);
  }
}
