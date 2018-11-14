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

    private ArrayList<Payload.PayloadType> wantSubtypes;

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
                                c.output(e);
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
        if (!wantSubtypes.isEmpty()) {
            Boolean haveMatch = false;
            for (Payload.PayloadType p : wantSubtypes) {
                if (e.getPayloadType() == p) {
                    haveMatch = true;
                    break;
                }
            }
            if (!haveMatch) {
                return false;
            }
        }
        return true;
    }

    /**
     * Add a match rule for a payload subtype
     *
     * @param p Payload type
     * @return EventFilter for chaining
     */
    public EventFilter wantSubtype(Payload.PayloadType p) {
        wantSubtypes.add(p);
        return this;
    }

    /**
     * Create new {@link EventFilter}
     */
    public EventFilter() {
        wantSubtypes = new ArrayList<Payload.PayloadType>();
    }
}
