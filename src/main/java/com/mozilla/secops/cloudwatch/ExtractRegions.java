package com.mozilla.secops.cloudwatch;

import com.mozilla.secops.parser.CloudWatch;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/** map AWS CloudWatch events to AWS regions */
public class ExtractRegions extends PTransform<PCollection<Event>, PCollection<String>> {
  private static final long serialVersionUID = 1L;

  /** Create new ExtractRegions */
  public ExtractRegions() {}

  @Override
  public PCollection<String> expand(PCollection<Event> es) {
    return es.apply(
        ParDo.of(
            new DoFn<Event, String>() {
              private static final long serialVersionUID = 1L;

              @ProcessElement
              public void processElement(ProcessContext c) {
                Event e = c.element();

                if (e.getPayloadType().equals(Payload.PayloadType.CLOUDWATCH)) {
                  CloudWatch cw = e.getPayload();
                  if ((cw == null) || (cw.getType() == null)) {
                    return;
                  }
                  c.output(cw.getEvent().getRegion());
                }
              }
            }));
  }
}
