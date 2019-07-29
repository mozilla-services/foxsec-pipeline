package com.mozilla.secops.metrics;

import java.io.Serializable;
import java.util.NoSuchElementException;
import org.apache.beam.sdk.io.UnboundedSource;
import org.apache.beam.sdk.io.UnboundedSource.CheckpointMark;
import org.apache.beam.sdk.io.UnboundedSource.CheckpointMark.NoopCheckpointMark;
import org.joda.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Unbounded reader for use with {@link CfgTickGenerator} */
class CfgTickUnboundedReader extends UnboundedSource.UnboundedReader<String>
    implements Serializable {
  private static final long serialVersionUID = 1L;

  private CfgTickUnboundedSource source;
  private Instant lastPoll;
  private Instant lastTick;
  private String current;
  private Logger log;

  /**
   * Initialize new {@link CfgTickUnboundedReader}
   *
   * @param source Source for reader
   */
  public CfgTickUnboundedReader(CfgTickUnboundedSource source) {
    this.source = source;
    current = null;
    lastTick = null;
    lastPoll = null;
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
    lastPoll = new Instant();
    generateCurrent();
    return true;
  }

  @Override
  public void close() {}

  @Override
  public boolean advance() {
    try {
      Thread.sleep(1000);
    } catch (InterruptedException exc) {
      return false;
    }
    lastPoll = new Instant();
    if ((lastPoll.getMillis() - lastTick.getMillis()) >= (source.getInterval() * 1000)) {
      generateCurrent();
      return true;
    }
    return false;
  }

  @Override
  public Instant getWatermark() {
    return lastPoll;
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
