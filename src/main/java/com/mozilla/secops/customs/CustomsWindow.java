package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;

/**
 * Helper class for windowing functions in the Customs pipeline.
 *
 * <p>For heuristics that use side inputs, both the main input and side input window must align.
 */
public class CustomsWindow {

  /** Transform to create a fixed ten minute window with early firings. */
  public static class FixedTenMinutes
      extends PTransform<PCollection<KV<String, Event>>, PCollection<KV<String, Event>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Event>> expand(PCollection<KV<String, Event>> input) {
      return input.apply(
          Window.<KV<String, Event>>into(FixedWindows.of(Duration.standardMinutes(10)))
              .triggering(
                  AfterWatermark.pastEndOfWindow()
                      .withEarlyFirings(
                          AfterProcessingTime.pastFirstElementInPane()
                              .plusDelayOf(Duration.standardSeconds(30))))
              .withAllowedLateness(Duration.ZERO)
              .accumulatingFiredPanes());
    }
  }
}
