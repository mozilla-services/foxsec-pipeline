package com.mozilla.secops.metrics;

import static org.junit.Assert.*;

import org.junit.Test;

public class TestCfgTickUnboundedReader {
  public TestCfgTickUnboundedReader() {}

  @Test(expected = IllegalArgumentException.class)
  public void cfgTickUnboundedReaderBadInterval() throws Exception {
    new CfgTickUnboundedReader(new CfgTickUnboundedSource("", 0));
  }
}
