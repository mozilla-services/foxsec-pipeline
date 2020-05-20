package com.mozilla.secops;

import static org.junit.Assert.*;

import com.carrotsearch.junitbenchmarks.BenchmarkOptions;
import com.carrotsearch.junitbenchmarks.BenchmarkRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

public class BenchCidrUtil {
  @Rule public TestRule benchmarkRun = new BenchmarkRule();

  @BenchmarkOptions(benchmarkRounds = 20, warmupRounds = 5)
  @Test
  public void benchmarkContains() throws Exception {
    CidrUtil c = new CidrUtil();

    // We could use loadInternalSubnets, but load a bunch manually here so the
    // size of the list is larger.
    for (int i = 0; i < 254; i++) {
      c.add(String.format("192.168.%d.0/24", i));
      c.add(String.format("10.0.%d.0/24", i));
    }

    for (int i = 0; i < 15000; i++) {
      c.contains("172.16.10.1");
    }
  }
}
