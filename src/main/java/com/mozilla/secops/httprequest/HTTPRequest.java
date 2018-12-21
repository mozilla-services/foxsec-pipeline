package com.mozilla.secops.httprequest;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.GLB;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import java.io.Serializable;
import java.util.Map;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.Mean;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.View;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.apache.beam.sdk.values.PCollectionView;
import org.apache.beam.sdk.values.TypeDescriptors;
import org.joda.time.DateTime;
import org.joda.time.Duration;

/**
 * {@link HTTPRequest} describes and implements a Beam pipeline for analysis of HTTP requests using
 * log data.
 */
public class HTTPRequest implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Composite transform to parse a {@link PCollection} containing events as strings and emit a
   * {@link PCollection} of {@link Event} objects.
   *
   * <p>The output is windowed into fixed windows of one minute. This function discards events that
   * are not considered HTTP requests.
   */
  public static class ParseAndWindow extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private final Boolean emitEventTimestamps;

    public ParseAndWindow(Boolean emitEventTimestamps) {
      this.emitEventTimestamps = emitEventTimestamps;
    }

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter =
          new EventFilter().setWantUTC(true).setOutputWithTimestamp(emitEventTimestamps);
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GLB));

      return col.apply(ParDo.of(new ParserDoFn()))
          .apply(EventFilter.getTransform(filter))
          .apply(Window.<Event>into(FixedWindows.of(Duration.standardMinutes(1))));
    }
  }

  /**
   * Composite transform which given a set of windowed {@link Event} types, emits a set of {@link
   * KV} objects where the key is the source address of the request and the value is the number of
   * requests for that source within the window.
   */
  public static class CountInWindow
      extends PTransform<PCollection<Event>, PCollection<KV<String, Long>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Long>> expand(PCollection<Event> col) {
      class GetSourceAddress extends DoFn<Event, String> {
        private static final long serialVersionUID = 1L;

        @ProcessElement
        public void processElement(ProcessContext c) {
          GLB g = c.element().getPayload();
          c.output(g.getSourceAddress());
        }
      }

      return col.apply(ParDo.of(new GetSourceAddress())).apply(Count.<String>perElement());
    }
  }

  /**
   * Composite transform which given a set of windowed {@link Event} types, emits a set of {@link
   * KV} objects where the key is the source address of the request and the value is the number of
   * client errors for that source within the window.
   */
  public static class CountErrorsInWindow
      extends PTransform<PCollection<Event>, PCollection<KV<String, Long>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Long>> expand(PCollection<Event> col) {
      class GetAddressErrors extends DoFn<Event, String> {
        private static final long serialVersionUID = 1L;

        @ProcessElement
        public void processElement(ProcessContext c) {
          GLB g = c.element().getPayload();
          Integer status = g.getStatus();
          if (status == null) {
            return;
          }
          if (status >= 400 && status < 500) {
            c.output(g.getSourceAddress());
          }
        }
      }

      return col.apply(ParDo.of(new GetAddressErrors())).apply(Count.<String>perElement());
    }
  }

  /**
   * {@link DoFn} to analyze key value pairs of source address and error count and emit a {@link
   * Result} for each address that exceeds the maximum client error rate
   */
  public static class ErrorRateAnalysis extends DoFn<KV<String, Long>, Result> {
    private static final long serialVersionUID = 1L;
    private final Long maxErrorRate;

    /**
     * Static initializer for {@link ErrorRateAnalysis}
     *
     * @param maxErrorRate Maximum client error rate per window
     */
    public ErrorRateAnalysis(Long maxErrorRate) {
      this.maxErrorRate = maxErrorRate;
    }

    @ProcessElement
    public void processElement(ProcessContext c, BoundedWindow w) {
      if (c.element().getValue() <= maxErrorRate) {
        return;
      }
      Result r = new Result(Result.ResultType.CLIENT_ERROR);
      r.setSourceAddress(c.element().getKey());
      r.setClientErrorCount(c.element().getValue());
      r.setMaxClientErrorRate(maxErrorRate);
      r.setWindowTimestamp(new DateTime(w.maxTimestamp()));
      c.output(r);
    }
  }

  /**
   * Composite transform that conducts threshold analysis using the configured threshold modifier
   * across a set of KV objects as returned by {@link CountInWindow}.
   */
  public static class ThresholdAnalysis
      extends PTransform<PCollection<KV<String, Long>>, PCollection<Result>> {
    private static final long serialVersionUID = 1L;

    private final Double thresholdModifier;
    private PCollectionView<Map<String, Boolean>> natView = null;

    /**
     * Static initializer for {@link ThresholdAnalysis}.
     *
     * @param thresholdModifier Threshold modifier to use for analysis.
     */
    public ThresholdAnalysis(Double thresholdModifier) {
      this.thresholdModifier = thresholdModifier;
    }

    /**
     * Static initializer for {@link ThresholdAnalysis}.
     *
     * @param thresholdModifier Threshold modifier to use for analysis.
     * @param natView Use {@link DetectNat} view during threshold analysis
     */
    public ThresholdAnalysis(
        Double thresholdModifier, PCollectionView<Map<String, Boolean>> natView) {
      this(thresholdModifier);
      this.natView = natView;
    }

    @Override
    public PCollection<Result> expand(PCollection<KV<String, Long>> col) {
      if (natView == null) {
        // If natView was not set then we just create an empty view for use as the side input
        natView =
            col.getPipeline()
                .apply(
                    Create.empty(
                        TypeDescriptors.kvs(TypeDescriptors.strings(), TypeDescriptors.booleans())))
                .apply(View.<String, Boolean>asMap());
      }

      PCollection<Long> counts =
          col.apply(
              "Extract counts",
              ParDo.of(
                  new DoFn<KV<String, Long>, Long>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      c.output(c.element().getValue());
                    }
                  }));
      final PCollectionView<Double> meanValue =
          counts.apply(Mean.<Long>globally().asSingletonView());

      PCollection<Result> ret =
          col.apply(
              ParDo.of(
                      new DoFn<KV<String, Long>, Result>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c, BoundedWindow w) {
                          Double mv = c.sideInput(meanValue);
                          Map<String, Boolean> nv = c.sideInput(natView);
                          if (c.element().getValue() >= (mv * thresholdModifier)) {
                            Boolean isNat = nv.get(c.element().getKey());
                            if (isNat != null && isNat) {
                              return;
                            }
                            Result r = new Result(Result.ResultType.THRESHOLD_ANALYSIS);
                            r.setCount(c.element().getValue());
                            r.setSourceAddress(c.element().getKey());
                            r.setMeanValue(mv);
                            r.setThresholdModifier(thresholdModifier);
                            r.setWindowTimestamp(new DateTime(w.maxTimestamp()));
                            c.output(r);
                          }
                        }
                      })
                  .withSideInputs(meanValue, natView));
      return ret;
    }
  }

  /**
   * {@link DoFn} to transform any generated {@link Result} objects into JSON for consumption by
   * output transforms.
   */
  public static class OutputFormat extends DoFn<Result, String> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void processElement(ProcessContext c) {
      c.output(c.element().toJSON());
    }
  }

  /** Runtime options for {@link HTTPRequest} pipeline. */
  public interface HTTPRequestOptions extends PipelineOptions, InputOptions, OutputOptions {
    @Description("Analysis threshold modifier")
    @Default.Double(75.0)
    Double getAnalysisThresholdModifier();

    void setAnalysisThresholdModifier(Double value);

    @Description("Maximum permitted client error rate per window")
    @Default.Long(30L)
    Long getMaxClientErrorRate();

    void setMaxClientErrorRate(Long value);

    @Description("Enable NAT detection for threshold analysis")
    @Default.Boolean(false)
    Boolean getNatDetection();

    void setNatDetection(Boolean value);
  }

  private static void runHTTPRequest(HTTPRequestOptions options) {
    Pipeline p = Pipeline.create(options);

    PCollection<Event> events =
        p.apply("input", options.getInputType().read(p, options))
            .apply("parse and window", new ParseAndWindow(false));

    PCollectionView<Map<String, Boolean>> natView = null;
    if (options.getNatDetection()) {
      natView = DetectNat.getView(events);
    }

    PCollection<String> threshResults =
        events
            .apply("per-client", new CountInWindow())
            .apply(
                "threshold analysis",
                new ThresholdAnalysis(options.getAnalysisThresholdModifier(), natView))
            .apply("output format", ParDo.of(new OutputFormat()));

    PCollection<String> errRateResults =
        events
            .apply("cerr per client", new CountErrorsInWindow())
            .apply(
                "error rate analysis",
                ParDo.of(new ErrorRateAnalysis(options.getMaxClientErrorRate())))
            .apply("output format", ParDo.of(new OutputFormat()));

    PCollectionList<String> resultsList = PCollectionList.of(threshResults).and(errRateResults);
    PCollection<String> results = resultsList.apply(Flatten.<String>pCollections());

    results.apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) {
    PipelineOptionsFactory.register(HTTPRequestOptions.class);
    HTTPRequestOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(HTTPRequestOptions.class);
    runHTTPRequest(options);
  }
}
