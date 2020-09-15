package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaContent;
import com.mozilla.secops.parser.Payload.PayloadType;
import java.util.Map;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.Distinct;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.View;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.apache.beam.sdk.values.TypeDescriptors;
import org.joda.time.Duration;

public class ContentServerVarianceDetector {

  /**
   * Return an empty variance view, suitable as a placeholder if variance detection is not desired
   *
   * @param p Pipeline to create view for
   * @return Empty {@link PCollectionView}
   */
  public static PCollectionView<Map<String, Boolean>> getEmptyView(Pipeline p) {
    return p.apply(
            "empty variance view",
            Create.empty(
                TypeDescriptors.kvs(TypeDescriptors.strings(), TypeDescriptors.booleans())))
        .apply(View.<String, Boolean>asMap());
  }

  /**
   * Execute transform returning a {@link PCollectionView} of ips accessing content server
   * resources, that can be used as a side input.
   *
   * <p>This is currently meant to work with the fixed 10 minute window based heuristics.
   *
   * @param events
   * @return {@link PCollectionView} representing output of analysis
   */
  public static PCollectionView<Map<String, Boolean>> getView(PCollection<Event> events) {
    return events
        .apply(
            "fixed ten min variance window",
            Window.<Event>into(FixedWindows.of(Duration.standardMinutes(10)))
                .triggering(
                    AfterWatermark.pastEndOfWindow()
                        .withEarlyFirings(
                            AfterProcessingTime.pastFirstElementInPane()
                                .plusDelayOf(Duration.standardSeconds(30))))
                .withAllowedLateness(Duration.ZERO)
                .accumulatingFiredPanes())
        .apply("variance view", new PresenceBased())
        .apply(View.<String, Boolean>asMap());
  }

  /** Provides a basic transform for detecting variance based on whether an ip exists */
  public static class PresenceBased
      extends PTransform<PCollection<Event>, PCollection<KV<String, Boolean>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Boolean>> expand(PCollection<Event> events) {
      return events
          .apply(
              "extract source ip",
              ParDo.of(
                  new DoFn<Event, KV<String, Boolean>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Event e = c.element();

                      if (e.getPayloadType().equals(PayloadType.FXACONTENT)) {
                        FxaContent d = e.getPayload();
                        if (d.getSourceAddress() != null) {
                          c.output(KV.of(d.getSourceAddress(), true));
                        }
                      }
                    }
                  }))
          .apply(Distinct.create());
    }
  }
}
