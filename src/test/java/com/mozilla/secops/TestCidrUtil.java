package com.mozilla.secops;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class TestCidrUtil {
  public TestCidrUtil() {}

  @Test
  public void fileInputCidrMatchTest() throws Exception {
    CidrUtil c = new CidrUtil("/testdata/cidrutil1.txt");
    assertTrue(c.contains("10.0.0.10"));
    assertFalse(c.contains("11.0.0.1"));
    assertTrue(c.contains("192.168.1.254"));
    assertFalse(c.contains("192.168.2.1"));
    assertTrue(c.contains("1.1.1.1"));
    assertFalse(c.contains("1.1.1.2"));
  }

  @Test
  public void cidrMatchTest() throws Exception {
    CidrUtil c = new CidrUtil();
    c.add("200.200.200.0/24");
    c.add("192.168.1.0/8");
    assertTrue(c.contains("200.200.200.200"));
    assertFalse(c.contains("200.201.200.200"));
  }

  @Test
  public void cidrLoadGcpSubnetsTest() throws Exception {
    CidrUtil c = new CidrUtil();
    c.add("192.168.1.0/24");
    assertTrue(c.contains("192.168.1.25"));
    assertFalse(c.contains("35.232.216.1"));
    assertFalse(c.contains("34.127.180.2"));
    c.loadGcpSubnets();
    assertTrue(c.contains("192.168.1.25"));
    assertTrue(c.contains("35.232.216.1"));
    assertTrue(c.contains("34.127.180.2"));
  }

  @Test
  public void resolvedHostMatchesTest() throws Exception {
    assertFalse(CidrUtil.resolvedCanonicalHostMatches("8.8.8.8", "test"));
    assertTrue(CidrUtil.resolvedCanonicalHostMatches("8.8.8.8", "dns\\.google$"));
    assertFalse(CidrUtil.resolvedCanonicalHostMatches("127.0.0.1", "dns\\.google$"));
    assertFalse(CidrUtil.resolvedCanonicalHostMatches("0.0.0.0", ".*"));
  }

  public void cidrLoadAwsSubnetsTest() throws Exception {
    CidrUtil c = new CidrUtil();
    c.add("192.168.1.0/24");
    assertFalse(c.contains("52.204.100.1"));
    assertTrue(c.contains("192.168.1.25"));
    c.loadAwsSubnets();
    assertTrue(c.contains("52.204.100.1"));
    assertTrue(c.contains("192.168.1.25"));
  }

  @Test
  public void cidrLoadInternalSubnetsTest() throws Exception {
    CidrUtil c = new CidrUtil();
    assertFalse(c.contains("52.204.100.1"));
    assertFalse(c.contains("192.168.1.25"));
    c.loadInternalSubnets();
    assertFalse(c.contains("52.204.100.1"));
    assertTrue(c.contains("192.168.1.25"));
  }
}
