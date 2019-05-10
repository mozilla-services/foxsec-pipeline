package com.mozilla.secops;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestStringDistance {
  public TestStringDistance() {}

  @Test
  public void stringDistanceTest() throws Exception {
    assertEquals(0, StringDistance.calculate("a", "a"));
    assertEquals(1, StringDistance.calculate("test", "test1"));
    assertEquals(2, StringDistance.calculate("test", "test10"));
    assertEquals(4, StringDistance.calculate("test", "abcd"));

    assertEquals(0.0, (double) StringDistance.ratio("test", "test"), 0.001);
    assertEquals(1.0, (double) StringDistance.ratio("aaaa", "bbbb"), 0.001);
    assertEquals(0.142, (double) StringDistance.ratio("test100", "test102"), 0.001);
  }
}
