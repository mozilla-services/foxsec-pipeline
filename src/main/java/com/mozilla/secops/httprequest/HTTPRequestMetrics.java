package com.mozilla.secops.httprequest;

import java.io.Serializable;
import org.apache.beam.sdk.metrics.Counter;
import org.apache.beam.sdk.metrics.Metrics;

/** {@link HTTPRequestMetrics} contains metrics for the {@link HTTPRequest} pipeline. */
public class HTTPRequestMetrics {

  /** Metrics for the various analysis transforms in {@link HTTPRequest} pipeline */
  public static class HeuristicMetrics implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String NAT_DETECTED = "nat_detected";
    private final Counter natDetected;

    /**
     * Initializer for {@link HeuristicMetrics}
     *
     * @param namespace String to categorize metric by heuristic
     */
    public HeuristicMetrics(String namespace) {
      natDetected = Metrics.counter(namespace, NAT_DETECTED);
    }

    /** A heuristic was triggered but it is from an ip believed to be a NAT */
    public void natDetected() {
      natDetected.inc();
    }
  }
}
