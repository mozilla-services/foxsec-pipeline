package com.mozilla.secops.parser;

import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.DoFn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.io.Serializable;

/**
 * Can be associated with {@link EventFilterRule} for payload matching
 */
public class EventFilterPayload implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * Properties match strings from various payload event types
     */
    public enum StringProperty {
        SECEVENT_ACTION,

        RAW_RAW
    }

    private Class<? extends PayloadBase> ptype;
    private Map<StringProperty, String> stringMatchers;

    /**
     * Return true if payload criteria matches
     *
     * @return True on match
     */
    public Boolean matches(Event e) {
        if (!(ptype.isInstance(e.getPayload()))) {
            return false;
        }
        for (Map.Entry<StringProperty, String> entry : stringMatchers.entrySet()) {
            if (!(e.getPayload().eventStringFilter(entry.getKey(), entry.getValue()))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Add a new simple string match to the payload filter
     *
     * @param property {@link EventFilterPayload.StringProperty}
     * @param s String to match against
     * @return EventFilterPayload for chaining
     */
    public EventFilterPayload withStringMatch(StringProperty property, String s) {
        stringMatchers.put(property, s);
        return this;
    }

    /**
     * Create new payload filter that matches against specified payload class
     *
     * @param ptype Payload class
     */
    public EventFilterPayload(Class<? extends PayloadBase> ptype) {
        this.ptype = ptype;
        stringMatchers = new HashMap<StringProperty, String>();
    }
}
