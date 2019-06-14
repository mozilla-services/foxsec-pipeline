package com.mozilla.secops.gatekeeper.guardduty;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.parser.*;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.*;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

/**
 * {@link GuardDutyPipeline} describes and implements a Beam pipeline for analysis of AWS CloudWatch
 * events, which may come from distinct source AWS services. CloudWatch from all services consist of
 * a set of common fields and a service specific "detail" JSON object
 */
public class GuardDutyPipeline implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for {@link GuardDutyPipeline} . */
  public interface GuardDutyOptions extends PipelineOptions, IOOptions {}

  /**
   * Composite transform to parse a {@link PCollection} containing events as strings and emit a
   * {@link PCollection} of {@link Event} objects.
   */
  public static class Parse extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private ParserCfg cfg;

    /**
     * Static initializer for {@link Parse} transform
     *
     * @param options Pipeline options
     */
    public Parse(GuardDutyOptions options) {
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> rawCloudWatchEventData) {
      EventFilter filter = new EventFilter();
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GUARDDUTY));

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

  /** An output transform that simply prints a string */
  public static class PrintKeys
      extends PTransform<PCollection<KV<String, Iterable<Event>>>, PDone> {
    private static final long serialVersionUID = 1L;

    @Override
    public PDone expand(PCollection<KV<String, Iterable<Event>>> input) {
      input.apply(
          ParDo.of(
              new DoFn<KV<String, Iterable<Event>>, Void>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  System.out.println(c.element().getKey());
                }
              }));
      return PDone.in(input.getPipeline());
    }
  }

  private static void runGuardDuty(GuardDutyOptions options) {

    Pipeline p = Pipeline.create(options);

    PCollection<Event> events =
        p.apply("input", new CompositeInput(options)).apply("parse", new Parse(options));

    PCollection<KV<String, Event>> byFindingType =
        events.apply(
            WithKeys.of(
                new SerializableFunction<Event, String>() {
                  private static final long serialVersionUID = 1L;

                  @Override
                  public String apply(Event input) {
                    GuardDuty gde = input.getPayload();
                    return gde.getFinding().getType();
                  }
                }));

    PCollection<KV<String, Iterable<Event>>> groupedByFindingType =
        byFindingType.apply(GroupByKey.<String, Event>create());

    groupedByFindingType.apply(new PrintKeys());

    p.run().waitUntilFinish();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) {
    PipelineOptionsFactory.register(GuardDutyOptions.class);

    GuardDutyOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(GuardDutyOptions.class);

    runGuardDuty(options);
  }
}
