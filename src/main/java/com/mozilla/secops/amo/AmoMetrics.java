package com.mozilla.secops.amo;

import java.io.Serializable;
import org.apache.beam.sdk.metrics.Counter;
import org.apache.beam.sdk.metrics.Metrics;

/** {@link AmoMetrics} contains metrics for the {@link Amo} pipeline */
public class AmoMetrics {

  /** Metrics for the various analysis transforms in the {@link Amo} pipeline */
  public static class HeuristicMetrics implements Serializable {
    private static final long serialVersionUID = 1L;
    static final String EVENT_TYPE_MATCH = "event_type_matched";
    private final Counter eventTypeMatched;

    /**
     * Initializer for {@link HeuristicMetrics}
     *
     * @param namespace String to categorize metric by heuristic
     */
    public HeuristicMetrics(String namespace) {
      eventTypeMatched = Metrics.counter(namespace, EVENT_TYPE_MATCH);
    }

    /** A transform received the correct event type to proceed with analysis */
    public void eventTypeMatched() {
      eventTypeMatched.inc();
    }
  }
}
