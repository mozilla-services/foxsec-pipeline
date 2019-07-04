package com.mozilla.secops.amo;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import java.io.IOException;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Flatten;
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
   */
  public static PCollection<Alert> executePipeline(
      Pipeline p, PCollection<String> input, AmoOptions options) throws IOException {
    // A valid iprepd configuration is required here, as values are pulled from iprepd
    if ((options.getOutputIprepd() == null) || (options.getOutputIprepdApikey() == null)) {
      throw new RuntimeException("iprepd pipeline configuration options are required");
    }

    ParserCfg cfg = ParserCfg.fromInputOptions(options);

    EventFilter filter = new EventFilter();
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
                    options.getOutputIprepd(),
                    options.getOutputIprepdApikey(),
                    options.getProject())));
    resultsList =
        resultsList.and(
            parsed.apply(
                "amo report restriction",
                new ReportRestriction(options.getMonitoredResourceIndicator())));
    return resultsList.apply("amo flatten output", Flatten.<Alert>pCollections());
  }

  /** Runtime options for {@link Amo} pipeline. */
  public interface AmoOptions extends PipelineOptions, IOOptions {}

  private static void runAmo(AmoOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input = p.apply("input", new CompositeInput(options));
    PCollection<Alert> alerts = executePipeline(p, input, options);

    alerts
        .apply("alert formatter", ParDo.of(new AlertFormatter(options)))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) throws IOException {
    PipelineOptionsFactory.register(AmoOptions.class);
    AmoOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(AmoOptions.class);
    runAmo(options);
  }
}
