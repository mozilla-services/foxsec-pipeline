package com.mozilla.secops;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TestSqsIO {
  public TestSqsIO() {}

  @Test
  public void SqsIOTestParseQueueInfo() throws Exception {
    String input = "https://queue.amazonaws.com/AAAAAAAA/queue:key:secret:us-east-1";

    String[] parts = SqsIO.parseQueueInfo(input);
    assertNotNull(parts);
    assertEquals(4, parts.length);
    assertEquals("https://queue.amazonaws.com/AAAAAAAA/queue", parts[0]);
    assertEquals("key", parts[1]);
    assertEquals("secret", parts[2]);
    assertEquals("us-east-1", parts[3]);
  }
}
