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
        SECEVENT_SOURCEADDRESS,
        SECEVENT_ACCOUNTID,

        RAW_RAW
    }

    private Class<? extends PayloadBase> ptype;
    private Map<StringProperty, String> stringMatchers;

    private ArrayList<StringProperty> stringSelectors;

    /**
     * Return true if payload criteria matches
     *
     * @param e Input event
     * @return True on match
     */
    public Boolean matches(Event e) {
        if (!(ptype.isInstance(e.getPayload()))) {
            return false;
        }
        for (Map.Entry<StringProperty, String> entry : stringMatchers.entrySet()) {
            String value = e.getPayload().eventStringValue(entry.getKey());
            if (value == null) {
                return false;
            }
            if (!(value.equals(entry.getValue()))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Return extracted keys from event based on string selectors
     *
     * @param e Input event
     * @return {@link ArrayList} of extracted keys
     */
    public ArrayList<String> getKeys(Event e) {
        ArrayList<String> ret = new ArrayList<String>();
        for (StringProperty s : stringSelectors) {
            String value = e.getPayload().eventStringValue(s);
            if (value == null) {
                return null;
            }
            ret.add(value);
        }
        return ret;
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
     * Add a string selector for filter keying operations
     *
     * @param property Property to extract for key
     * @return EventFilterPayload for chaining
     */
    public EventFilterPayload withStringSelector(StringProperty property) {
        stringSelectors.add(property);
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
        stringSelectors = new ArrayList<StringProperty>();
    }
}
