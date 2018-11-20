package com.mozilla.secops.customs;

import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.alert.Alert;

import java.io.Serializable;
import java.util.Collection;

/**
 * Operate in conjunction with {@link RateLimitAnalyzer} to apply analysis criterion
 * to incoming event stream.
 */
public class RateLimitCriterion extends DoFn<KV<String, Iterable<Event>>, KV<String, Alert>> {
    private static final long serialVersionUID = 1L;

    private final Alert.AlertSeverity severity;
    private final String customsMeta;
    private final long limit;

    private Logger log;

    /**
     * {@link RateLimitCriterion} static initializer
     *
     * @param severity Severity to use for generated alerts
     * @param customsMeta Customs metadata tag to place on alert
     * @param limit Generate alert if count meets or exceeds limit value in window
     */
    public RateLimitCriterion(Alert.AlertSeverity severity, String customsMeta, long limit) {
        this.severity = severity;
        this.customsMeta = customsMeta;
        this.limit = limit;
    }

    @Setup
    public void setup() {
        log = LoggerFactory.getLogger(RateLimitCriterion.class);
        log.info("initialized new rate limit criterion analyzer, {} {} {}", severity, customsMeta, limit);
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
        KV<String, Iterable<Event>> e = c.element();

        String key = e.getKey();
        Iterable<Event> values = e.getValue();
        if (!(values instanceof Collection)) {
            log.warn("value was not instance of collection");
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
