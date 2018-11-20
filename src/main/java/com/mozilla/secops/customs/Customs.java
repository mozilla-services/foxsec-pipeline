package com.mozilla.secops.customs;

import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.options.Validation.Required;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.transforms.windowing.BoundedWindow;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.AfterPane;
import org.apache.beam.sdk.transforms.windowing.SlidingWindows;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.state.StateSpec;
import org.apache.beam.sdk.state.StateSpecs;
import org.apache.beam.sdk.state.ValueState;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.Parser;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.SecEvent;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;

import org.joda.time.DateTime;
import org.joda.time.Duration;

import java.io.Serializable;
import java.util.Collection;

/**
 * Implements various rate limiting and analysis heuristics on {@link SecEvent} streams
 */
public class Customs implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * Detect limit violations on login failure based on source address
     */
    public static class RlLoginFailureSourceAddress extends PTransform<PCollection<Event>,
        PCollection<Alert>> {
        private static final long serialVersionUID = 1L;

        private final Long threshold;
        private final Long windowLength;
        private final Boolean emitTimestamps;

        public RlLoginFailureSourceAddress(Boolean emitTimestamps, Long threshold, Long windowLength) {
            this.threshold = threshold;
            this.windowLength = windowLength;
            this.emitTimestamps = emitTimestamps;
        }

        @Override
        public PCollection<Alert> expand(PCollection<Event> col) {
            EventFilter filter = new EventFilter()
                .setOutputWithTimestamp(emitTimestamps);
            filter.addRule(new EventFilterRule()
                .wantSubtype(Payload.PayloadType.SECEVENT)
                .addPayloadFilter(new EventFilterPayload(SecEvent.class)
                    .withStringMatch(EventFilterPayload.StringProperty.SECEVENT_ACTION, "loginFailure")));
            filter.addKeyingSelector(new EventFilterRule()
                .wantSubtype(Payload.PayloadType.SECEVENT)
                .addPayloadFilter(new EventFilterPayload(SecEvent.class)
                    .withStringSelector(EventFilterPayload.StringProperty.SECEVENT_SOURCEADDRESS)));

            return col.apply(RateLimitAnalyzer.getTransform(
                new RateLimitAnalyzer("rl_login_failure_source_address")
                .setFilter(filter)
                .setAlertCriteria(threshold, Alert.AlertSeverity.INFORMATIONAL)
                .setAnalysisWindow(windowLength, 5L)
                .setAlertSuppression(900L)));
        }
    }

    /**
     * Runtime options for {@link Customs} pipeline.
     */
    public interface CustomsOptions extends PipelineOptions, InputOptions, OutputOptions {
        @Description("login failure by source address; rate limit threshold")
        @Default.Long(3L)
        Long getLoginFailureBySourceAddressLimitThreshold();
        void setLoginFailureBySourceAddressLimitThreshold(Long value);

        @Description("login failure by source address; analysis window length in seconds")
        @Default.Long(900L)
        Long getLoginFailureBySourceAddressLimitWindowLength();
        void setLoginFailureBySourceAddressLimitWindowLength(Long value);
    }

    private static void runCustoms(CustomsOptions options) {
        Pipeline p = Pipeline.create(options);

        PCollection<Alert> rlalerts = p.apply("input", options.getInputType().read(p, options))
            .apply("parse", ParDo.of(new ParserDoFn()))
            .apply(new RlLoginFailureSourceAddress(
                false,
                options.getLoginFailureBySourceAddressLimitThreshold(),
                options.getLoginFailureBySourceAddressLimitWindowLength()
            ));

        rlalerts.apply(ParDo.of(new AlertFormatter()))
            .apply("output", OutputOptions.compositeOutput(options));

        p.run();
    }

    /**
     * Entry point for Beam pipeline.
     *
     * @param args Runtime arguments.
     */
    public static void main(String[] args) {
        PipelineOptionsFactory.register(CustomsOptions.class);
        CustomsOptions options =
            PipelineOptionsFactory.fromArgs(args).withValidation().as(CustomsOptions.class);
        runCustoms(options);
    }
}
