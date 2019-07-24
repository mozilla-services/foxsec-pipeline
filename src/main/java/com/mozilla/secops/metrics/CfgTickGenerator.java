package com.mozilla.secops.metrics;

import org.apache.beam.sdk.io.Read;
import org.apache.beam.sdk.io.Read.Unbounded;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;

/** Generate periodic configuration ticks */
public class CfgTickGenerator extends PTransform<PBegin, PCollection<String>> {
  private static final long serialVersionUID = 1L;

  private final String message;
  private final Integer interval;
  private final long maxNumRecords;

  /**
   * Initialize new {@link CfgTickGenerator}
   *
   * <p>The source for this transform is unbounded. The maxNumRecords parameter is intended to place
   * an upper limit on the number of records generated for testing purposes; under normal
   * circumstances this parameter should be set to -1.
   *
   * @param message Message to emit
   * @param interval Seconds between emissions
   * @param maxNumRecords Only generate specified number of records and stop
   */
  public CfgTickGenerator(String message, Integer interval, long maxNumRecords) {
    this.message = message;
    this.interval = interval;
    this.maxNumRecords = maxNumRecords;
  }

  @Override
  public PCollection<String> expand(PBegin begin) {
    Unbounded<String> unbounded = Read.from(new CfgTickUnboundedSource(message, interval));

    PTransform<PBegin, PCollection<String>> transform;
    if (maxNumRecords <= 0) {
      transform = unbounded;
    } else {
      transform = unbounded.withMaxNumRecords(maxNumRecords);
    }

    return begin.getPipeline().apply(transform);
  }
}
