package com.mozilla.secops.input;

import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.TupleTag;

/**
 * Input tuple isolation for multiplexed input
 *
 * <p>DoFn which takes a collection of events as input, and returns an output tuple with two tuple
 * tags, one for events with FLAG_OK, and the other for any events which have a different event flag
 * set.
 */
public class MultiInputIsolator extends DoFn<KV<String, Event>, KV<String, Event>> {
  private static final long serialVersionUID = 1L;

  private final TupleTag<KV<String, Event>> okEvents;
  private final TupleTag<KV<String, Event>> discardEvents;

  /**
   * Initialize new multi input isolator
   *
   * @param okEvents OK events tuple tag
   * @param discardEvents Discard events tuple tag
   */
  public MultiInputIsolator(
      TupleTag<KV<String, Event>> okEvents, TupleTag<KV<String, Event>> discardEvents) {
    this.okEvents = okEvents;
    this.discardEvents = discardEvents;
  }

  @ProcessElement
  public void processElement(ProcessContext c, MultiOutputReceiver out) {
    KV<String, Event> e = c.element();

    switch (e.getValue().getEventFlag()) {
      case FLAG_OK:
        out.get(okEvents).output(e);
        break;
      default:
        out.get(discardEvents).output(e);
        break;
    }
  }
}
