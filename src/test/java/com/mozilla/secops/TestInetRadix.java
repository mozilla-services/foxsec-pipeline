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

    r = new InetRadix();

    assertFalse(r.contains("1.2.3.3"));
    assertFalse(r.contains("1.2.3.4"));
    assertFalse(r.contains("1.2.3.5"));
    r.add("1.2.3.4/32");
    assertFalse(r.contains("1.2.3.3"));
    assertTrue(r.contains("1.2.3.4"));
    assertFalse(r.contains("1.2.3.5"));
    r.add("1.2.3.4/30");
    assertFalse(r.contains("1.2.3.3"));
    assertTrue(r.contains("1.2.3.4"));
    assertTrue(r.contains("1.2.3.5"));
    assertTrue(r.contains("1.2.3.6"));
    assertTrue(r.contains("1.2.3.7"));
    assertFalse(r.contains("1.2.3.8"));

    r.add("1.2.4.4/30");
    assertFalse(r.contains("1.2.3.3"));
    assertTrue(r.contains("1.2.3.4"));
    assertTrue(r.contains("1.2.3.5"));
    assertTrue(r.contains("1.2.3.6"));
    assertTrue(r.contains("1.2.3.7"));
    assertFalse(r.contains("1.2.3.8"));
    assertFalse(r.contains("1.2.4.3"));
    assertTrue(r.contains("1.2.4.4"));
    assertTrue(r.contains("1.2.4.5"));
    assertTrue(r.contains("1.2.4.6"));
    assertTrue(r.contains("1.2.4.7"));
    assertFalse(r.contains("1.2.4.8"));
    r.add("1.2.4.4/32");
    assertFalse(r.contains("1.2.3.3"));
    assertTrue(r.contains("1.2.3.4"));
    assertTrue(r.contains("1.2.3.5"));
    assertTrue(r.contains("1.2.3.6"));
    assertTrue(r.contains("1.2.3.7"));
    assertFalse(r.contains("1.2.3.8"));
    assertFalse(r.contains("1.2.4.3"));
    assertTrue(r.contains("1.2.4.4"));
    assertTrue(r.contains("1.2.4.5"));
    assertTrue(r.contains("1.2.4.6"));
    assertTrue(r.contains("1.2.4.7"));
    assertFalse(r.contains("1.2.4.8"));

    r = new InetRadix();
    r.add("1.0.0.0/24");
    r.add("1.0.0.1/24");
    r.add("1.0.0.2/24");
    assertTrue(r.contains("1.0.0.0"));
    assertTrue(r.contains("1.0.0.1"));
    assertTrue(r.contains("1.0.0.2"));
    assertTrue(r.contains("1.0.0.200"));
    assertFalse(r.contains("1.0.1.0"));

    r = new InetRadix();
    r.add("10.0.0.0/16");
    r.add("10.2.0.0/16");
    r.add("10.4.0.0/16");
    r.add("10.6.0.0/16");
    r.add("10.8.0.0/16");
    r.add("10.10.0.0/16");
    r.add("10.12.0.0/16");
    r.add("10.14.0.0/16");
    r.add("10.16.0.0/16");
    r.add("10.18.0.0/16");
    r.add("10.20.0.0/24");
    r.add("10.22.0.0/24");
    r.add("10.24.0.0/24");
    r.add("10.26.0.0/24");
    r.add("10.28.0.0/24");

    assertTrue(r.contains("10.0.0.1"));
    assertFalse(r.contains("10.1.0.1"));
    assertTrue(r.contains("10.2.0.1"));
    assertFalse(r.contains("10.3.0.1"));
    assertTrue(r.contains("10.4.0.1"));
    assertFalse(r.contains("10.5.0.1"));
    assertTrue(r.contains("10.6.0.1"));
    assertFalse(r.contains("10.7.0.1"));
    assertTrue(r.contains("10.8.0.1"));

    assertTrue(r.contains("10.24.0.200"));
    assertFalse(r.contains("10.24.1.200"));
  }
}
