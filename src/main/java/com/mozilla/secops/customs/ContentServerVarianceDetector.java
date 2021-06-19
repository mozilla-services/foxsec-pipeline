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
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.apache.beam.sdk.values.TypeDescriptors;

/**
 * Provides transforms to detect if an ip is making a variety of requests to the content server or
 * is just abusing auth server APIs. This is similar to the variance substrings for {@link
 * com.mozilla.secops.httprequest.heuristics.EndpointAbuseAnalysis} in the HTTPRequest pipeline.
 *
 * <p>Currently, this has only one transform, whether an ip exists in the content server logs.
 * Eventually this could be extended to only consider certain events (such as metrics) or meet more
 * complex conditions.
 */
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
   * @param events Input events
   * @return {@link PCollectionView} representing output of analysis
   */
  public static PCollectionView<Map<String, Boolean>> getView(PCollection<Event> events) {
    return events.apply("variance view", new PresenceBased()).apply(View.<String, Boolean>asMap());
  }

  /** Provides a basic transform for detecting variance based on whether an ip exists */
  public static class PresenceBased
      extends PTransform<PCollection<Event>, PCollection<KV<String, Boolean>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Boolean>> expand(PCollection<Event> events) {
      return events
          .apply(
              "key by source address",
              ParDo.of(
                  new DoFn<Event, KV<String, Event>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Event e = c.element();

                      if (e.getPayloadType().equals(PayloadType.FXACONTENT)) {
                        FxaContent d = e.getPayload();
                        if (d.getSourceAddress() != null) {
                          c.output(KV.of(d.getSourceAddress(), e));
                        }
                      }
                    }
                  }))
          .apply("fixed ten min variance window", new CustomsWindow.FixedTenMinutes())
          .apply(
              ParDo.of(
                  new DoFn<KV<String, Event>, KV<String, Boolean>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      KV<String, Event> kv = c.element();
                      c.output(KV.of(kv.getKey(), true));
                    }
                  }))
          .apply(Distinct.create());
    }
  }
}
