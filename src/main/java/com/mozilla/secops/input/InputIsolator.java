package com.mozilla.secops.input;

import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.TupleTag;

/**
 * Input tuple isolation
 *
 * <p>DoFn which takes a collection of events as input, and returns an output tuple with two tuple
 * tags, one for events with FLAG_OK, and the other for any events which have a different event flag
 * set.
 */
public class InputIsolator extends DoFn<Event, Event> {
  private static final long serialVersionUID = 1L;

  private final TupleTag<Event> okEvents;
  private final TupleTag<Event> discardEvents;

  /**
   * Initialize new input isolator
   *
   * @param okEvents OK events tuple tag
   * @param discardEvents Discard events tuple tag
   */
  public InputIsolator(TupleTag<Event> okEvents, TupleTag<Event> discardEvents) {
    this.okEvents = okEvents;
    this.discardEvents = discardEvents;
  }

  @ProcessElement
  public void processElement(ProcessContext c, MultiOutputReceiver out) {
    Event e = c.element();

    switch (e.getEventFlag()) {
      case FLAG_OK:
        out.get(okEvents).output(e);
        break;
      default:
        out.get(discardEvents).output(e);
        break;
    }
  }
}
