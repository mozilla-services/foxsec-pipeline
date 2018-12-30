package com.mozilla.secops;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.GLB;
import com.mozilla.secops.parser.Payload;
import java.util.Map;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Distinct;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.View;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;

/**
 * Provides a basic NAT detection transform
 *
 * <p>Currently this transform only operates on GLB log data, and is based on the detection of
 * multiple user agents being identified for requests within the window for the same source IP
 * address.
 *
 * <p>The output from the transform is a {@link PCollection} of KV pairs where the key is a source
 * IP address identified in the window and the value is a boolean indicating if there is a
 * possibility the source address is a NAT gateway.
 */
public class DetectNat extends PTransform<PCollection<Event>, PCollection<KV<String, Boolean>>> {
  private static final long serialVersionUID = 1L;

  private static final Long UAMARKPROBABLE = 2L;

  /**
   * Execute the transform returning a {@link PCollectionView} suitable for use as a side input
   *
   * @param events Input events
   * @return {@link PCollectionView} representing output of analysis
   */
  public static PCollectionView<Map<String, Boolean>> getView(PCollection<Event> events) {
    return events.apply(new DetectNat()).apply(View.<String, Boolean>asMap());
  }

  @Override
  public PCollection<KV<String, Boolean>> expand(PCollection<Event> events) {
    PCollection<KV<String, Long>> perSourceUACounts =
        events
            .apply(
                "extract user agents",
                ParDo.of(
                    new DoFn<Event, KV<String, String>>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        Event e = c.element();

                        KV<String, String> output = null;
                        // Just support GLB events for now here
                        if (e.getPayloadType() == Payload.PayloadType.GLB) {
                          GLB g = e.getPayload();
                          if (g.getSourceAddress() != null && g.getUserAgent() != null) {
                            output = KV.of(g.getSourceAddress(), g.getUserAgent());
                          }
                        } else {
                          return;
                        }
                        if (output != null) {
                          c.output(output);
                        }
                      }
                    }))
            .apply(Distinct.<KV<String, String>>create())
            .apply(Count.<String, String>perKey());

    // Operate solely on the UA output right now here, but this should be expanded with more
    // detailed analysis
    return perSourceUACounts.apply(
        "detect nat",
        ParDo.of(
            new DoFn<KV<String, Long>, KV<String, Boolean>>() {
              private static final long serialVersionUID = 1L;

              @ProcessElement
              public void processElement(ProcessContext c) {
                KV<String, Long> input = c.element();
                if (input.getValue() >= UAMARKPROBABLE) {
                  c.output(KV.of(input.getKey(), true));
                } else {
                  c.output(KV.of(input.getKey(), false));
                }
              }
            }));
  }
}
