package com.mozilla.secops.identity;

import org.junit.Test;
import org.junit.Rule;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;

public class TestIdentityManager {
    public TestIdentityManager() {
    }

    @Test
    public void identityManagerFromResourceTest() throws Exception {
        IdentityManager mgr = IdentityManager.loadFromResource("/testdata/identitymanager.json");
        assertNotNull(mgr);

        assertEquals("testuser@mozilla.com", mgr.lookupAlias("testuser"));
        assertNull(mgr.lookupAlias("unknown"));

        assertNull(mgr.getIdentity("worf@mozilla.com"));
        assertNotNull(mgr.getIdentity("testuser@mozilla.com"));
    }

    @Test
    public void identityManagerNotifyTest() throws Exception {
        IdentityManager mgr = IdentityManager.loadFromResource("/testdata/identitymanager.json");
        assertNotNull(mgr);

        // Test standard case, identity with fragment and aliases
        String testId = "wcrusher@mozilla.com";
        Identity id = mgr.getIdentity(testId);
        assertNotNull(id);
        assertEquals("testing-wcrusher@mozilla.com",
            id.getEmailNotifyDirect(mgr.getDefaultNotification()));
        assertEquals("wcrusher", id.getFragment());

        // Identity missing fragment, should not notify directly
        testId = "testuser@mozilla.com";
        id = mgr.getIdentity(testId);
        assertNotNull(id);
        assertNull(id.getEmailNotifyDirect(mgr.getDefaultNotification()));
        assertNull(id.getFragment());

        // Identity with direct email format override
        testId = "wriker@mozilla.com";
        id = mgr.getIdentity(testId);
        assertNotNull(id);
        assertEquals("holodeck-riker@mozilla.com",
            id.getEmailNotifyDirect(mgr.getDefaultNotification()));
        assertEquals("riker", id.getFragment());
    }
}
