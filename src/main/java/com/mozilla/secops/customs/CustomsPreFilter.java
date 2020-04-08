package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.Payload;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/**
 * Basic filtering of ingested events prior to analysis application
 *
 * <p>This transform will filter any events from the input collection that are not returned in
 * {@link Customs#featureSummaryRegistration}.
 */
public class CustomsPreFilter extends PTransform<PCollection<Event>, PCollection<Event>> {
  private static final long serialVersionUID = 1L;

  @Override
  public PCollection<Event> expand(PCollection<Event> col) {
    return col.apply(
        "prefilter",
        ParDo.of(
            new DoFn<Event, Event>() {
              private static final long serialVersionUID = 1L;

              private ArrayList<FxaAuth.EventSummary> types;

              @Setup
              public void setup() {
                types = Customs.featureSummaryRegistration();
              }

              @ProcessElement
              public void processElement(ProcessContext c) {
                Event e = c.element();

                if (e.getPayloadType().equals(Payload.PayloadType.CFGTICK)) {
                  c.output(e);
                  return;
                }

                FxaAuth.EventSummary s = CustomsUtil.authGetEventSummary(e);
                if (s == null) {
                  return;
                }
                if (!types.contains(s)) {
                  return;
                }
                c.output(e);
              }
            }));
  }
}
