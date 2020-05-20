package com.mozilla.secops;

import static org.junit.Assert.*;

import org.junit.Test;

public class TestInetRadix {
  @Test
  public void testLookup() throws Exception {
    InetRadix r = new InetRadix();

    r.add("192.168.0.0/24");
    r.add("10.10.10.10/32");
    r.add("1.0.0.0/8");
    r.add("192.168.10.0/28");

    assertFalse(r.contains("10.0.0.1"));
    assertFalse(r.contains("192.168.1.1"));
    assertFalse(r.contains("10.10.10.9"));
    assertFalse(r.contains("10.10.10.11"));
    assertFalse(r.contains("255.255.255.255"));
    assertFalse(r.contains("0.0.0.0"));
    assertFalse(r.contains("192.168.10.16"));

    assertTrue(r.contains("192.168.0.10"));
    assertTrue(r.contains("10.10.10.10"));
    assertTrue(r.contains("1.0.0.1"));
    assertTrue(r.contains("1.255.255.255"));
    assertTrue(r.contains("192.168.10.1"));
    assertTrue(r.contains("192.168.10.15"));
  }
}
