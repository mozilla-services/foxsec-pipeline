package com.mozilla.secops.metrics;

import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.apache.beam.sdk.coders.Coder;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.io.UnboundedSource;
import org.apache.beam.sdk.io.UnboundedSource.CheckpointMark;
import org.apache.beam.sdk.options.PipelineOptions;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Unbounded source for use with {@link CfgTickGenerator} */
class CfgTickUnboundedSource extends UnboundedSource<String, CheckpointMark> {
  private static final long serialVersionUID = 1L;

  private final UUID instanceId;
  private final String message;
  private final Integer interval;
  private Instant lastRecordTimestamp;
  private Logger log;

  /**
   * Initialize new {@link CfgTickUnboundedSource}
   *
   * @param message Configuration tick message to emit
   * @param interval Emission interval in seconds
   */
  public CfgTickUnboundedSource(String message, Integer interval) {
    instanceId = UUID.randomUUID();
    this.message = message;
    this.interval = interval;
    log = LoggerFactory.getLogger(CfgTickUnboundedSource.class);
  }

  /**
   * Get message that will be sent by this source
   *
   * @return Record string
   */
  public String getMessage() {
    return message;
  }

  /**
   * Generate a new configuration tick
   *
   * @return Record string
   */
  public String generateNewRecord() {
    lastRecordTimestamp = new Instant();
    return getMessage();
  }

  /**
   * Return emission interval
   *
   * @return Integer
   */
  public Integer getInterval() {
    return interval;
  }

  /**
   * Request the timestamp associated with the last generated configuration tick
   *
   * @return Instant
   */
  public Instant getRecordTimestamp() {
    return lastRecordTimestamp;
  }

  @Override
  public Coder<CheckpointMark> getCheckpointMarkCoder() {
    return null;
  }

  @Override
  public Coder<String> getOutputCoder() {
    return StringUtf8Coder.of();
  }

  @Override
  public List<? extends UnboundedSource<String, CheckpointMark>> split(
      int desired, PipelineOptions options) {
    return Collections.<UnboundedSource<String, CheckpointMark>>singletonList(this);
  }

  @Override
  public boolean requiresDeduping() {
    return false;
  }

  @Override
  public UnboundedSource.UnboundedReader<String> createReader(
      PipelineOptions options, CheckpointMark checkpointMark) {
    return new CfgTickUnboundedReader(this);
  }

  /**
   * Get source instance ID
   *
   * @return UUID
   */
  public UUID getInstanceId() {
    return instanceId;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof CfgTickUnboundedSource)) {
      return false;
    }
    CfgTickUnboundedSource t = (CfgTickUnboundedSource) o;
    return getInstanceId().equals(t.getInstanceId());
  }

  @Override
  public int hashCode() {
    return instanceId.hashCode();
  }
}
