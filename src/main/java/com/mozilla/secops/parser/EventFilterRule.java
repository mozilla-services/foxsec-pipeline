package com.mozilla.secops.parser;

import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.DoFn;

import java.util.ArrayList;
import java.io.Serializable;

/**
 * Rule within an event filter
 */
public class EventFilterRule implements Serializable {
    private static final long serialVersionUID = 1L;

    private Payload.PayloadType wantSubtype;
    private Normalized.Type wantNormalizedType;
    private ArrayList<EventFilterPayload> payloadFilters;

    /**
     * Test if event matches rule
     *
     * @param e Event to match against rule
     * @return True if event matches
     */
    public Boolean matches(Event e) {
        if (wantSubtype != null) {
            if (e.getPayloadType() != wantSubtype) {
                return false;
            }
        }
        if (wantNormalizedType != null) {
            if (!(e.getNormalized().isOfType(wantNormalizedType))) {
                return false;
            }
        }
        for (EventFilterPayload p : payloadFilters) {
            if (!p.matches(e)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Add payload filter
     *
     * @param p Payload filter criteria
     * @return EventFilterRule for chaining
     */
    public EventFilterRule addPayloadFilter(EventFilterPayload p) {
        payloadFilters.add(p);
        return this;
    }

    /**
     * Add match criteria for a payload subtype
     *
     * @param p Payload type
     * @return EventFilterRule for chaining
     */
    public EventFilterRule wantSubtype(Payload.PayloadType p) {
        wantSubtype = p;
        return this;
    }

    /**
     * Add match criteria for a normalized event type
     *
     * @param n Normalized event type
     * @return EventFilterRule for chaining
     */
    public EventFilterRule wantNormalizedType(Normalized.Type n) {
        wantNormalizedType = n;
        return this;
    }

    /**
     * Create new empty {@link EventFilterRule}
     */
    public EventFilterRule() {
        payloadFilters = new ArrayList<EventFilterPayload>();
    }
}
