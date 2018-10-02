package com.mozilla.secops;

import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.io.gcp.bigquery.BigQueryIO;
import org.apache.beam.sdk.io.gcp.bigquery.BigQueryIO.Write;
import org.apache.beam.sdk.io.gcp.bigquery.BigQueryIO.Write.CreateDisposition;
import org.apache.beam.sdk.io.gcp.bigquery.BigQueryIO.Write.WriteDisposition;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.options.Validation.Required;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.Mean;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.api.services.bigquery.model.TableRow;

import com.google.gson.Gson;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Parser;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.GLB;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.joda.time.Duration;
import java.time.ZoneId;
import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.UUID;


public class HeavyHitters implements Serializable {
    private static class Result implements Serializable {
        private final String addr;
        private final Long count;
        private final String timestamp;
        private final Double meanValue;
        private final Double thresholdMod;
        private final String id;

        Result(String addr, Long count, Double mv, Double thresholdMod) {
            this.addr = addr;
            this.count = count;
            this.meanValue = mv;
            this.thresholdMod = thresholdMod;

            id = UUID.randomUUID().toString();

            // XXX Just set the current timestamp here for now
            DateTimeFormatter f = DateTimeFormat.forPattern("YYYY-MM-dd HH:mm:ss");
            timestamp = f.print(new DateTime());
        }

        public String getResultId() {
            return id;
        }

        @Override
        public boolean equals(Object o) {
            Result t = (Result)o;
            return getResultId().equals(t.getResultId());
        }

        static Result fromKV(KV<String, Long> e, Double mv, Double thresholdMod) {
            Result ret = new Result(e.getKey(), e.getValue(), mv, thresholdMod);
            return ret;
        }
    }

    private static class ParseFn extends DoFn<String, String> {
        private Parser ep;

        @Setup
        public void Setup() {
            // The parser is not serializable so initialize it in the setup function
            ep = new Parser();
        }

        @ProcessElement
        public void processElement(ProcessContext c) {
            Event e = ep.parse(c.element());
            if (e.getPayloadType() == Payload.PayloadType.GLB) {
                GLB g = e.getPayload();
                // XXX Output with current timestamp for now, this should probably parse the
                // timestamp out of the GLB record
                c.outputWithTimestamp(g.getSourceAddress(), new Instant());
            }
        }
    }

    static class AnalyzeFn extends PTransform<PCollection<KV<String, Long>>, PCollection<Result>> {
        private Double thresholdMod;

        AnalyzeFn(Double thresholdMod) {
            this.thresholdMod = thresholdMod;
        }

        @Override
        public PCollection<Result> expand(PCollection<KV<String, Long>> col) {
            // Create a PCollectionView that contains the mean value of all request counts
            // across the window, this gets used as a side input
            PCollection<Long> counts = col.apply("Get request counts", ParDo.of(
                        new DoFn<KV<String, Long>, Long>() {
                            @ProcessElement
                            public void processElement(ProcessContext c) {
                                c.output(c.element().getValue());
                            }
                        }
                        ));
            final PCollectionView<Double> meanVal = counts.apply("Mean of request counts",
                    Mean.<Long>globally().asSingletonView());

            // Filter items that do not exceed the mean value with the threshold modifier
            // applied
            PCollection<Result> ret = col.apply("Analyze", ParDo.of(
                        new DoFn<KV<String, Long>, Result>() {
                            @ProcessElement
                            public void processElement(ProcessContext c) {
                                Double mv = c.sideInput(meanVal);
                                Result r = Result.fromKV(c.element(), mv, thresholdMod);
                                if (c.element().getValue() >= (mv * thresholdMod)) {
                                    c.output(r);
                                }
                            }
                        }
                        ).withSideInputs(meanVal));
            return ret;
        }
    }

    static class FileTransformFn extends DoFn<Result, String> {
        @ProcessElement
        public void processElement(ProcessContext c) {
            c.output(new Gson().toJson(c.element()));
        }
    }

    static class RowTransformFn extends DoFn<Result, TableRow> {
        @ProcessElement
        public void processElement(ProcessContext c) {
            Gson g = new Gson();
            TableRow r = g.fromJson(g.toJson(c.element()), TableRow.class);
            c.output(r);
        }
    }

    public interface HeavyHittersOptions extends PipelineOptions {
        @Description("Path to file to read input from")
        String getInputFile();
        void setInputFile(String value);

        @Description("Pubsub topic to read input from")
        String getInputPubsub();
        void setInputPubsub(String value);

        @Description("Path to file to write output to")
        String getOutputFile();
        void setOutputFile(String value);

        @Description("BigQuery output specification")
        String getOutputBigQuery();
        void setOutputBigQuery(String value);

        @Description("Analysis threshold modifier")
        @Default.Double(75.0)
        Double getAnalysisThresholdModifier();
        void setAnalysisThresholdModifier(Double value);
    }

    static void runHeavyHitters(HeavyHittersOptions options) {
        Pipeline p = Pipeline.create(options);

        PCollection<String> input;
        if (options.getInputFile() != null) {
            input = p.apply("Read input from file", TextIO.read().from(options.getInputFile()));
        } else if (options.getInputPubsub() != null) {
            input = p.apply("Read input from pubsub", PubsubIO.readStrings()
                    .fromTopic(options.getInputPubsub()));
        } else {
            throw new IllegalArgumentException("no input specified");
        }

        PCollection<Result> data = input.apply("Parse events", ParDo.of(new ParseFn()))
            .apply("Window events", Window.<String>into(FixedWindows.of(Duration.standardMinutes(2))))
            .apply("Per-element count", Count.<String>perElement())
            .apply("Threshold analysis", new AnalyzeFn(options.getAnalysisThresholdModifier()));

        if (options.getOutputFile() != null) {
            data.apply("Conversion for text output", ParDo.of(new FileTransformFn()))
                .apply("Output to text file", TextIO.write().to(options.getOutputFile()));
        } else if (options.getOutputBigQuery() != null) {
            data.apply("BigQuery TableRow conversion", ParDo.of(new RowTransformFn()))
                .apply("Output to BigQuery", BigQueryIO.writeTableRows()
                        .to(options.getOutputBigQuery())
                        .withCreateDisposition(BigQueryIO.Write.CreateDisposition.CREATE_NEVER)
                        .withWriteDisposition(BigQueryIO.Write.WriteDisposition.WRITE_APPEND));
        } else {
            throw new IllegalArgumentException("no output specified");
        }

        p.run();
    }

    public static void main(String[] args) {
        HeavyHittersOptions options =
            PipelineOptionsFactory.fromArgs(args).withValidation().as(HeavyHittersOptions.class);
        runHeavyHitters(options);
    }
}
