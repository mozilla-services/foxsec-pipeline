package com.mozilla.secops.window;

import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.GlobalWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;

/**
 * Window input type into global windows, triggering at a specific interval and discarding fired
 * panes.
 */
public class GlobalTriggers<T> extends PTransform<PCollection<T>, PCollection<T>> {
  private static final long serialVersionUID = 1L;

  private final int tseconds;

  /**
   * Initialize new {@link GlobalTriggers}
   *
   * @param tseconds Trigger every specified seconds
   */
  public GlobalTriggers(int tseconds) {
    this.tseconds = tseconds;
  }

  @Override
  public PCollection<T> expand(PCollection<T> input) {
    return input.apply(
        "global triggers",
        Window.<T>into(new GlobalWindows())
            .triggering(
                Repeatedly.forever(
                    AfterProcessingTime.pastFirstElementInPane()
                        .plusDelayOf(Duration.standardSeconds(tseconds))))
            .discardingFiredPanes());
  }
}
