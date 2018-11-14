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

        public RlLoginFailureSourceAddress(Long threshold, Long windowLength) {
            this.threshold = threshold;
            this.windowLength = windowLength;
        }

        @Override
        public PCollection<Alert> expand(PCollection<Event> col) {
            return col.apply(ParDo.of(new ActionFilter("loginFailure")))
                .apply(ParDo.of(new ElementExtractor(ElementExtractor.ExtractElement.SOURCEADDRESS)))
                .apply("Sliding window", Window.<KV<String, Event>>into(
                    SlidingWindows.of(Duration.standardSeconds(windowLength))
                    .every(Duration.standardSeconds(5)))
                )
                .apply("GBK event", GroupByKey.<String, Event>create())
                .apply(ParDo.of(new LimitCriterion(Alert.AlertSeverity.INFORMATIONAL,
                    "rl_login_failure_source_address", threshold)))
                .apply("Fixed window",
                    Window.<KV<String, Alert>>into(FixedWindows.of(Duration.standardMinutes(15)))
                        .triggering(Repeatedly.forever(
                            AfterWatermark.pastEndOfWindow()
                            .withEarlyFirings(AfterPane.elementCountAtLeast(1))
                        ))
                        .withAllowedLateness(Duration.ZERO)
                        .discardingFiredPanes()
                    )
                .apply("GBK alert", GroupByKey.<String, Alert>create())
                .apply(ParDo.of(new Suppressor()));
        }
    }

    /**
     * Suppress duplicate in-window alerts based on key
     */
    public static class Suppressor extends DoFn<KV<String, Iterable<Alert>>, Alert> {
        private static final long serialVersionUID = 1L;

        private Logger log;

        @StateId("suppression")
        private final StateSpec<ValueState<Boolean>> suppression =
            StateSpecs.value();

        public Suppressor() {
            log = LoggerFactory.getLogger(Suppressor.class);
        }

        @ProcessElement
        public void processElement(ProcessContext c, BoundedWindow w,
            @StateId("suppression") ValueState<Boolean> suppress) {
            KV<String, Iterable<Alert>> el = c.element();
            String key = el.getKey();
            Iterable<Alert> alertval = el.getValue();

            if (!(alertval instanceof Collection)) {
                return;
            }
            Alert[] alerts = ((Collection<Alert>) alertval).toArray(new Alert[0]);
            if (alerts.length == 0) {
                return;
            }

            Boolean sflag = suppress.read();
            if (sflag != null && sflag) {
                log.info("suppressing additional in-window alert for {}", key);
                return;
            }
            suppress.write(true);
            log.info("emitting alert for {} in window {} [{}]", key, w.maxTimestamp(),
                w.maxTimestamp().getMillis());

            // Write the earlist timestamp for the alert set we can find
            DateTime min = null;
            int idx = -1;
            for (int i = 0; i < alerts.length; i++) {
                if (min == null) {
                    min = alerts[i].getTimestamp();
                    idx = i;
                    continue;
                }
                if (alerts[i].getTimestamp().isBefore(min)) {
                    min = alerts[i].getTimestamp();
                    idx = i;
                }
            }
            log.info("emit {} {} {}", alerts[idx].getAlertId(), alerts[idx].getCategory(),
                alerts[idx].getTimestamp());
            c.output(alerts[idx]);
        }
    }

    /**
     * Generate alerts based on comparison of iterable with supplied limit criterion
     */
    public static class LimitCriterion extends DoFn<KV<String, Iterable<Event>>, KV<String, Alert>> {
        private static final long serialVersionUID = 1L;

        private final Alert.AlertSeverity severity;
        private final String customsMeta;
        private final long limit;

        private Logger log;

        /**
         * {@link LimitCriterion} static initializer
         */
        public LimitCriterion(Alert.AlertSeverity severity, String customsMeta, long limit) {
            this.severity = severity;
            this.customsMeta = customsMeta;
            this.limit = limit;
        }

        @Setup
        public void setup() {
            log = LoggerFactory.getLogger(LimitCriterion.class);
            log.info("initialized new limit criterion analyzer, {} {} {}", severity, customsMeta, limit);
        }

        @ProcessElement
        public void processElement(ProcessContext c) {
            KV<String, Iterable<Event>> e = c.element();

            String key = e.getKey();
            Iterable<Event> values = e.getValue();
            if (!(values instanceof Collection)) {
                return;
            }
            Event[] events = ((Collection<Event>) values).toArray(new Event[0]);
            if (events.length < limit) {
                return;
            }

            Alert alert = new Alert();
            alert.setCategory("customs");
            alert.addMetadata("customs_category", customsMeta);
            alert.addMetadata("customs_suspected", key);
            alert.setSeverity(severity);
            c.output(KV.of(key, alert));
        }
    }

    /**
     * {@link DoFn} to convert an {@link Event} into a {@link KV} where the key is a
     * specific known field in the event, and the value is the event itself.
     */
    public static class ElementExtractor extends DoFn<Event, KV<String, Event>> {
        private static final long serialVersionUID = 1L;

        /**
         * Possible elements for extraction
         */
        public enum ExtractElement {
            /** SecEvent source address */
            SOURCEADDRESS
        }

        private final ExtractElement etype;

        public ElementExtractor(ExtractElement etype) {
            this.etype = etype;
        }

        @ProcessElement
        public void processElement(ProcessContext c) {
            Event e = c.element();
            if (e == null) {
                return;
            }
            SecEvent s = e.getPayload();
            if (s == null) {
                return;
            }
            String k;
            switch (etype) {
                case SOURCEADDRESS:
                    k = s.getSecEventData().getSourceAddress();
                    break;
                default:
                    throw new IllegalArgumentException("invalid extraction element");
            }
            if (k == null) {
                return;
            }
            c.output(KV.of(k, e));
        }
    }

    /**
     * Filter input {@link PCollection} based on the specified action, returning only events
     * that match the specified action
     */
    public static class ActionFilter extends DoFn<Event, Event> {
        private static final long serialVersionUID = 1L;

        private String match;

        public ActionFilter(String match) {
            this.match = match;
        }

        @ProcessElement
        public void processElement(ProcessContext c) {
            Event e = c.element();
            if (e != null && e.getPayloadType() == Payload.PayloadType.SECEVENT) {
                SecEvent s = e.getPayload();
                String action = s.getSecEventData().getAction();
                if (action != null && action.equals(match)) {
                    c.output(e);
                }
            }
        }
    }

    /**
     * Parse input event strings, returning any parsed SECEVENT
     */
    public static class Parse extends DoFn<String, Event> {
        private static final long serialVersionUID = 1L;

        private Logger log;
        private Parser ep;
        private Long parseCount;

        private final Boolean emitEventTimestamps;

        public Parse(Boolean emitEventTimestamps) {
            this.emitEventTimestamps = emitEventTimestamps;
        }

        @Setup
        public void setup() {
            ep = new Parser();
            log = LoggerFactory.getLogger(Parse.class);
            log.info("initialized new parser");
        }

        @StartBundle
        public void StartBundle() {
            log.info("processing new bundle");
            parseCount = 0L;
        }

        @FinishBundle
        public void FinishBundle() {
            log.info("{} events processed in bundle", parseCount);
        }

        @ProcessElement
        public void processElement(ProcessContext c) {
            Event e = ep.parse(c.element());
            if (e != null && e.getPayloadType() == Payload.PayloadType.SECEVENT) {
                parseCount++;
                if (emitEventTimestamps) {
                    c.outputWithTimestamp(e, e.getTimestamp().toInstant());
                } else {
                    c.output(e);
                }
            }
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

        @Description("login failure by source address; analysis window length")
        @Default.Long(900L)
        Long getLoginFailureBySourceAddressLimitWindowLength();
        void setLoginFailureBySourceAddressLimitWindowLength(Long value);
    }

    private static void runCustoms(CustomsOptions options) {
        Pipeline p = Pipeline.create(options);

        PCollection<Alert> rlalerts = p.apply("input", options.getInputType().read(p, options))
            .apply("parse", ParDo.of(new Parse(false)))
            .apply(new RlLoginFailureSourceAddress(
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
