package com.mozilla.secops.metrics;

import java.io.Serializable;
import java.util.NoSuchElementException;
import org.apache.beam.sdk.io.UnboundedSource;
import org.apache.beam.sdk.io.UnboundedSource.CheckpointMark;
import org.apache.beam.sdk.io.UnboundedSource.CheckpointMark.NoopCheckpointMark;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Unbounded reader for use with {@link CfgTickGenerator} */
class CfgTickUnboundedReader extends UnboundedSource.UnboundedReader<String>
    implements Serializable {
  private static final long serialVersionUID = 1L;

  private CfgTickUnboundedSource source;
  private Instant lastTick;
  private String current;
  private int interval;
  private Logger log;

  /**
   * Initialize new {@link CfgTickUnboundedReader}
   *
   * @param source Source for reader
   */
  public CfgTickUnboundedReader(CfgTickUnboundedSource source) {
    if (source.getInterval() <= 0) {
      throw new IllegalArgumentException("interval must be > 0");
    }
    this.source = source;
    current = null;
    lastTick = null;
    interval = source.getInterval() * 1000;
    log = LoggerFactory.getLogger(CfgTickUnboundedReader.class);
  }

  private void generateCurrent() {
    log.info("generating new configuration tick");
    current = source.generateNewRecord();
    lastTick = source.getRecordTimestamp();
  }

  @Override
  public String getCurrent() throws NoSuchElementException {
    if (current == null) {
      throw new NoSuchElementException();
    }
    return current;
  }

  @Override
  public Instant getCurrentTimestamp() throws NoSuchElementException {
    if (current == null) {
      throw new NoSuchElementException();
    }
    return lastTick;
  }

  @Override
  public boolean start() {
    generateCurrent();
    return true;
  }

  @Override
  public void close() {}

  @Override
  public long getSplitBacklogBytes() {
    if (shouldEmit()) {
      return source.getMessage().getBytes().length;
    }
    return 0L;
  }

  private boolean shouldEmit() {
    // Determine if we should emit a new configuration tick or not
    return (Instant.now().getMillis() - lastTick.getMillis()) >= interval;
  }

  @Override
  public boolean advance() {
    if (shouldEmit()) {
      generateCurrent();
      return true;
    }
    return false;
  }

  @Override
  public Instant getWatermark() {
    Instant r = Instant.now().minus(Duration.standardSeconds(5));
    if (lastTick.isAfter(r)) {
      return lastTick;
    } else {
      return r;
    }
  }

  @Override
  public CheckpointMark getCheckpointMark() {
    return new NoopCheckpointMark();
  }

  @Override
  public CfgTickUnboundedSource getCurrentSource() {
    return source;
  }
}
