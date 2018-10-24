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
}
