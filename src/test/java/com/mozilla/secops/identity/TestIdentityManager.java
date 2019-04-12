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
    assertNull(mgr.lookupAlias("unknown"));
    assertEquals("testuser@mozilla.com", mgr.lookupAlias("testuser@mozilla.com"));

    assertNull(mgr.getIdentity("worf@mozilla.com"));
    assertNotNull(mgr.getIdentity("testuser@mozilla.com"));
  }

  @Test
  public void identityManagerNotifyTest() throws Exception {
    IdentityManager mgr = IdentityManager.load("/testdata/identitymanager.json");
    assertNotNull(mgr);

    // Test standard case, identity with fragment and aliases
    String testId = "wcrusher@mozilla.com";
    Identity id = mgr.getIdentity(testId);
    assertNotNull(id);
    assertEquals(
        "testing-wcrusher@mozilla.com", id.getEmailNotifyDirect(mgr.getDefaultNotification()));
    assertEquals("wcrusher", id.getFragment());

    // Identity missing fragment, should not notify directly
    testId = "testuser@mozilla.com";
    id = mgr.getIdentity(testId);
    assertNotNull(id);
    assertNull(id.getEmailNotifyDirect(mgr.getDefaultNotification()));
    assertFalse(id.getSlackNotifyDirect(mgr.getDefaultNotification()));
    assertFalse(id.getSlackConfirmationAlertFeatureFlag(mgr.getDefaultFeatureFlags()));
    assertNull(id.getFragment());

    // Identity with direct email format override
    testId = "wriker@mozilla.com";
    id = mgr.getIdentity(testId);
    assertNotNull(id);
    assertEquals(
        "holodeck-riker@mozilla.com", id.getEmailNotifyDirect(mgr.getDefaultNotification()));
    assertEquals("riker", id.getFragment());
    assertTrue(id.getSlackNotifyDirect(mgr.getDefaultNotification()));
    assertTrue(id.getSlackConfirmationAlertFeatureFlag(mgr.getDefaultFeatureFlags()));
  }

  @Test
  public void identityManagerNotifyNoDefaultsTest() throws Exception {
    IdentityManager mgr = IdentityManager.load("/testdata/identitymanager_nodefaults.json");
    assertNotNull(mgr);

    Identity id = mgr.getIdentity("wriker@mozilla.com");
    assertNotNull(id);
    assertEquals(
        "holodeck-riker@mozilla.com", id.getEmailNotifyDirect(mgr.getDefaultNotification()));
    assertEquals("riker", id.getFragment());
    assertTrue(id.getSlackNotifyDirect(mgr.getDefaultNotification()));
    assertTrue(id.getSlackConfirmationAlertFeatureFlag(mgr.getDefaultFeatureFlags()));

    id = mgr.getIdentity("wcrusher@mozilla.com");
    assertNotNull(id);
    assertNull(id.getEmailNotifyDirect(mgr.getDefaultNotification()));
    assertFalse(id.getSlackNotifyDirect(mgr.getDefaultNotification()));
    assertFalse(id.getSlackConfirmationAlertFeatureFlag(mgr.getDefaultFeatureFlags()));
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
}
