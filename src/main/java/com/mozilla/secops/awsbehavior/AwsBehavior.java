package com.mozilla.secops.awsbehavior;

import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.PCollection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.Parser;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;

import org.joda.time.Duration;

import java.io.IOException;
import java.io.Serializable;

public class AwsBehavior implements Serializable {
    private static final long serialVersionUID = 1L;

    public static class ParseAndWindow extends PTransform<PCollection<String>,
           PCollection<Event>> {
        private static final long serialVersionUID = 1L;

        @Override
        public PCollection<Event> expand(PCollection<String> col) {
            EventFilter filter = new EventFilter();
            filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.CLOUDTRAIL));


            return col.apply(ParDo.of(new ParserDoFn()))
                .apply(EventFilter.getTransform(filter))
                .apply(Window.<Event>into(FixedWindows.of(Duration.standardMinutes(5))));
        }
    }

    public static class Analyze extends DoFn<Event, Alert> {
        private static final long serialVersionUID = 1L;

        private final String cmmanagerPath;
        private final String idmanagerPath;
        private CloudtrailMatcherManager cmmanager;
        private IdentityManager idmanager;
        private Logger log;

        public Analyze(AwsBehaviorOptions options) {
            idmanagerPath = options.getIdentityManagerPath();
            cmmanagerPath = options.getCloudtrailMatcherManagerPath();
        }

        @Setup
        public void setup() throws IOException {
            log = LoggerFactory.getLogger(Analyze.class);
            idmanager = IdentityManager.loadFromResource(idmanagerPath);
            cmmanager = CloudtrailMatcherManager.loadFromResource(cmmanagerPath);
        }

        @ProcessElement
        public void processElement(ProcessContext c) {
            EventFilter filter = new EventFilter();
            // For each "event matcher"
            //      - Does this event match?
            //      - If yes:
            //          - Fire off an alert
            //              - Including optional event description, account name, identity name, resource
        }
    }

    /**
     * Runtime options for {@link AwsBehavior} pipeline.
     */
    public interface AwsBehaviorOptions extends PipelineOptions, InputOptions, OutputOptions {
        @Description("Identity manager configuration; resource path")
        @Default.String("/identitymanager.json")
        String getIdentityManagerPath();
        void setIdentityManagerPath(String value);

        @Description("Cloudtrail matcher manager configuration; resource path")
        @Default.String("/event_matchers.json")
        String getCloudtrailMatcherManagerPath();
        void setCloudtrailMatcherManagerPath(String value);
    }

    private static void runAwsBehavior(AwsBehaviorOptions options) throws IllegalArgumentException {
        // TODO:
        // Fan out to filters depending on resource/config

        Pipeline p = Pipeline.create(options);

        PCollection<Alert> alerts = p.apply("input", options.getInputType().read(p, options))
            .apply("parse and window", new ParseAndWindow())
            .apply(ParDo.of(new Analyze(options)));

        alerts.apply(ParDo.of(new AlertFormatter()))
            .apply("output", OutputOptions.compositeOutput(options));

        p.run();
    }

    /**
     * Entry point for Beam pipeline.
     *
     * @param args Runtime arguments.
     */
    public static void main(String[] args) throws Exception {
        PipelineOptionsFactory.register(AwsBehaviorOptions.class);
        AwsBehaviorOptions options =
            PipelineOptionsFactory.fromArgs(args).withValidation().as(AwsBehaviorOptions.class);
        runAwsBehavior(options);
    }
}
