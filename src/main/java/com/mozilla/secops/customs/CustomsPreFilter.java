package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.Payload;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.TupleTag;

/**
 * Basic filtering of ingested events prior to analysis application
 *
 * <p>This DoFn will split events up based on type. Configuration ticks are emitted in the main
 * output collection which contains FxA authentication server events.
 *
 * <p>For FXAAUTH events, this DoFn will filter any events from the input collection that are not
 * returned in {@link Customs#featureSummaryRegistration}.
 */
public class CustomsPreFilter extends DoFn<Event, Event> {
  private static final long serialVersionUID = 1L;

  /** Tuple tag used for FxA auth events */
  public static final TupleTag<Event> TAG_FXA_AUTH_EVENTS =
      new TupleTag<Event>() {
        private static final long serialVersionUID = 1L;
      };

  /** Tuple tag used for private relay events */
  public static final TupleTag<Event> TAG_RELAY_EVENTS =
      new TupleTag<Event>() {
        private static final long serialVersionUID = 1L;
      };

  public static final TupleTag<Event> TAG_FXA_CONTENT_EVENTS =
      new TupleTag<Event>() {
        private static final long serialVersionUID = 1L;
      };

  private ArrayList<FxaAuth.EventSummary> types;

  @Setup
  public void setup() {
    types = Customs.featureSummaryRegistration();
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Event e = c.element();

    if (e.getPayloadType().equals(Payload.PayloadType.CFGTICK)) {
      // Emit configuration ticks in the main output collection
      c.output(e);
      return;
    }

    if (e.getPayloadType().equals(Payload.PayloadType.PRIVATE_RELAY)) {
      c.output(TAG_RELAY_EVENTS, e);
      return;
    }

    if (e.getPayloadType().equals(Payload.PayloadType.FXACONTENT)) {
      c.output(TAG_FXA_CONTENT_EVENTS, e);
      return;
    }

    // Otherwise this is an FXAAUTH event; verify the event summary matches something
    // we want and emit it in the main output collection
    FxaAuth.EventSummary s = CustomsUtil.authGetEventSummary(e);
    if (s == null) {
      return;
    }
    if (!types.contains(s)) {
      return;
    }
    c.output(e);
  }
}
