package com.mozilla.secops.metrics;

import java.io.IOException;
import java.io.Serializable;
import org.apache.beam.sdk.io.UnboundedSource;

/**
 * Checkpoint mark for CfgTickUnboundedSource This is a noop but we need a serializable class to
 * have a coder in order to avoid pipeline construction failures.
 */
class CfgTickCheckpointMark implements UnboundedSource.CheckpointMark, Serializable {
  private static final long serialVersionUID = 1L;

  @Override
  public void finalizeCheckpoint() throws IOException {
    // nothing to do
  }
}
