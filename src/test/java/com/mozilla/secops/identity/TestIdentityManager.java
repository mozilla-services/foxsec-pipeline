package com.mozilla.secops.identity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import org.junit.Test;

public class TestIdentityManager {
  public TestIdentityManager() {}

  @Test
  public void identityManagerFromResourceTest() throws Exception {
    IdentityManager mgr = IdentityManager.load("/testdata/identitymanager.json");
    assertNotNull(mgr);

    assertEquals("testuser@mozilla.com", mgr.lookupAlias("testuser"));
    assertEquals("testuser@mozilla.com", mgr.lookupAlias("test user"));
    assertNull(mgr.lookupAlias("unknown"));
    assertNull(mgr.lookupAlias(""));
    assertNull(mgr.lookupAlias(null));
    assertEquals("testuser@mozilla.com", mgr.lookupAlias("testuser@mozilla.com"));

    assertNull(mgr.getIdentity("worf@mozilla.com"));
    assertNotNull(mgr.getIdentity("testuser@mozilla.com"));
  }

  @Test
  public void identityManagerNotifyTest() throws Exception {
    IdentityManager mgr = IdentityManager.load("/testdata/identitymanager.json");
    assertNotNull(mgr);

    // Test standard case
    String testId = "wcrusher@mozilla.com";
    Identity id = mgr.getIdentity(testId);
    assertNotNull(id);
    assertEquals("testing-wcrusher@mozilla.com", id.getAlert().getEmail());
    assertTrue(id.shouldAlertViaEmail());
    assertTrue(id.shouldNotifyViaEmail());

    // Identity missing notification preferences, should not notify directly
    testId = "testuser@mozilla.com";
    id = mgr.getIdentity(testId);
    assertNotNull(id);
    assertNull(id.getEscalateTo());
    assertFalse(id.shouldAlertViaSlack());
    assertFalse(id.shouldNotifyViaSlack());
    assertFalse(id.shouldAlertViaEmail());
    assertFalse(id.shouldNotifyViaEmail());
    assertNull(id.getAlert());
    assertNull(id.getNotify());

    // Identity with mixed contact methods
    testId = "wriker@mozilla.com";
    id = mgr.getIdentity(testId);
    assertNotNull(id);
    assertEquals("holodeck-riker@mozilla.com", id.getAlert().getEmail());
    assertEquals("picard@mozilla.com", id.getEscalateTo());
    assertTrue(id.shouldAlertViaSlack());
    assertTrue(id.shouldNotifyViaEmail());
    assertFalse(id.shouldNotifyViaSlack());
    assertFalse(id.shouldAlertViaEmail());
  }

  @Test
  public void identityManagerAwsAccountMapLookupTest() throws Exception {
    IdentityManager mgr = IdentityManager.load("/testdata/identitymanager.json");
    assertNotNull(mgr);

    Map<String, String> m = mgr.getAwsAccountMap();
    assertNull(m.get("000000000"));
    String ret = m.get("123456789");
    assertNotNull(ret);
    assertEquals("riker-vacationing-on-risa", ret);
  }

  @Test
  public void identityManagerNamedSubnetTest() throws Exception {
    IdentityManager mgr = IdentityManager.load("/testdata/identitymanager.json");
    assertNotNull(mgr);
    assertEquals("office", mgr.lookupNamedSubnet("fd00:0:0:0:0:0:0:1"));
    assertNull(mgr.lookupNamedSubnet("fd01:0:0:0:0:0:0:1"));
    assertNull(mgr.lookupNamedSubnet(null));
  }

  @Test(expected = IllegalArgumentException.class)
  public void identityManagerNamedSubnetInvalidTest() throws Exception {
    IdentityManager mgr = IdentityManager.load("/testdata/identitymanager.json");
    assertNotNull(mgr);
    mgr.lookupNamedSubnet("invalid");
  }
}
