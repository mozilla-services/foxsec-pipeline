package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/** Basic filtering of ingested events prior to analysis application */
public class CustomsPreFilter extends PTransform<PCollection<Event>, PCollection<Event>> {
  private static final long serialVersionUID = 1L;

  /**
   * Paths that will be filtered from the input stream
   *
   * <p>Requests to these paths will be filtered early prior to passing the collection on. Shuffle
   * operations downstream become too expensive with inclusion of these endpoints.
   */
  public static final String[] EXCLUDEPATHS = new String[] {"/v1/verify", "/v1/account/devices"};

  @Override
  public PCollection<Event> expand(PCollection<Event> col) {
    return col.apply(
        "prefilter",
        ParDo.of(
            new DoFn<Event, Event>() {
              private static final long serialVersionUID = 1L;

              @ProcessElement
              public void processElement(ProcessContext c) {
                Event e = c.element();

                if (e.getPayloadType().equals(Payload.PayloadType.CFGTICK)) {
                  c.output(e);
                  return;
                }

                String path = CustomsUtil.authGetPath(e);
                if (path == null) {
                  return;
                }
                for (String i : EXCLUDEPATHS) {
                  if (path.equals(i)) {
                    return;
                  }
                }

                c.output(e);
              }
            }));
  }
}
