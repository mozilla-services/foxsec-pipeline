package com.mozilla.secops;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import org.junit.Test;

public class TestNatUtil {

  @Test
  public void TestGivenNullPathReturnsEmptyMap() {
    Map<String, Boolean> gwList = NatUtil.loadGatewayList(null);
    assertTrue(gwList.isEmpty());
  }

  @Test
  public void TestGivenEmptyPathReturnsEmptyMap() {
    Map<String, Boolean> gwList = NatUtil.loadGatewayList("");
    assertTrue(gwList.isEmpty());
  }

  @Test
  public void TestGivenInvalidPathReturnsEmptyMap() {
    Map<String, Boolean> gwList = NatUtil.loadGatewayList("not/a/path");
    assertTrue(gwList.isEmpty());
  }

  @Test
  public void TestGivenValidPathReturnMapWithAllItemsSingle() {
    Map<String, Boolean> gwList = NatUtil.loadGatewayList("/testdata/natutil1.txt");
    assertEquals(1, gwList.size());
    assertTrue(gwList.get("192.168.1.2"));
  }

  @Test
  public void TestGivenValidPathReturnMapWithAllItemsMany() {
    Map<String, Boolean> gwList = NatUtil.loadGatewayList("/testdata/natutil2.txt");
    assertEquals(3, gwList.size());
    assertTrue(gwList.get("192.168.0.0"));
    assertTrue(gwList.get("10.0.0.0"));
    assertTrue(gwList.get("255.255.255.255"));
  }
}
