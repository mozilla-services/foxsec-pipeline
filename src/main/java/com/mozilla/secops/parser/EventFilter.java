package com.mozilla.secops.parser;

import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.DoFn;

import java.util.ArrayList;
import java.io.Serializable;

/**
 * Event filtering and matching
 */
public class EventFilter implements Serializable {
    private static final long serialVersionUID = 1L;

    private ArrayList<EventFilterRule> rules;

    private Boolean wantUTC;
    private Boolean outputWithTimestamp;

    /**
     * Get composite transform to apply filter to event stream
     *
     * @param filter Event filter
     * @return Transform
     */
    public static PTransform<PCollection<Event>, PCollection<Event>> getTransform(EventFilter filter) {
        return new PTransform<PCollection<Event>, PCollection<Event>>() {
            private static final long serialVersionUID = 1L;

            @Override
            public PCollection<Event> expand(PCollection<Event> input) {
                return input.apply(ParDo.of(
                    new DoFn<Event, Event>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c) {
                            Event e = c.element();
                            if (filter.matches(e)) {
                                // If wantUTC is set, drop any event that has a timestamp with a
                                // non-UTC timezone
                                if (filter.getWantUTC()) {
                                    if (!e.getTimestamp().getZone().getID().equals("Etc/UTC")) {
                                        return;
                                    }
                                }

                                if (filter.getOutputWithTimestamp()) {
                                    c.outputWithTimestamp(e, e.getTimestamp().toInstant());
                                } else {
                                    c.output(e);
                                }
                            }
                        }
                    }
                ));
            }
        };
    }

    /**
     * Test if event matches filter
     *
     * @param e Event to match against filter
     * @return True if filter matches
     */
    public Boolean matches(Event e) {
        for (EventFilterRule r : rules) {
            if (r.matches(e)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Add new rule to filter
     *
     * @param rule New rule to add
     */
    public void addRule(EventFilterRule rule) {
        rules.add(rule);
    }

    /**
     * Set timestamp handling for event output
     *
     * @param flag If true use event timestamp on output
     * @return EventFilter for chaining
     */
    public EventFilter setOutputWithTimestamp(Boolean flag) {
        outputWithTimestamp = flag;
        return this;
    }

    /**
     * Get timestamp handling for event output
     *
     * @return True if events should be emitted with timestamp
     */
    public Boolean getOutputWithTimestamp() {
        return outputWithTimestamp;
    }

    /**
     * Choose to ignore non-UTC timezone events
     *
     * @param flag If true, drop events with parsed timezones that are not UTC
     * @return EventFilter for chaining
     */
    public EventFilter setWantUTC(Boolean flag) {
        wantUTC = flag;
        return this;
    }

    /**
     * Get UTC handling parameter
     *
     * @return True if non-UTC events should be dropped in filter
     */
    public Boolean getWantUTC() {
        return wantUTC;
    }

    /**
     * Create new {@link EventFilter}
     */
    public EventFilter() {
        rules = new ArrayList<EventFilterRule>();
        wantUTC = false;
        outputWithTimestamp = false;
    }
}
