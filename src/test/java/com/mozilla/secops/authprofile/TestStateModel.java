package com.mozilla.secops.authprofile;

import org.junit.Test;
import org.junit.Rule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import org.joda.time.DateTime;

import com.mozilla.secops.state.State;
import com.mozilla.secops.state.DatastoreStateInterface;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class TestStateModel {
    @Rule
    public final EnvironmentVariables environmentVariables
        = new EnvironmentVariables();

    private void testEnv() {
        environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
        environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
        environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
        environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
    }

    public TestStateModel() {
    }

    @Test
    public void StateModelTest() throws Exception {
        testEnv();
        State s = new State(new DatastoreStateInterface("authprofile", "teststatemodel"));
        s.initialize();

        assertNull(StateModel.get("nonexist", s));

        StateModel sm = new StateModel("riker");
        assertNotNull(sm);
        sm.set(s);

        sm = StateModel.get("riker", s);
        assertNotNull(sm);
        assertEquals(sm.getEntries().size(), 0);

        assertTrue(sm.updateEntry("127.0.0.1")); // Assert true for new address
        assertEquals(sm.getEntries().size(), 1);
        sm.set(s);
        sm = StateModel.get("riker", s);
        assertEquals(sm.getEntries().size(), 1);
        assertFalse(sm.updateEntry("127.0.0.1")); // Assert false for update existing
        sm.set(s);

        assertTrue(sm.updateEntry("10.0.0.1"));
        assertEquals(sm.getEntries().size(), 2);
        sm.set(s);
        sm = StateModel.get("riker", s);
        assertEquals(sm.getEntries().size(), 2);

        sm = new StateModel("picard");
        assertNotNull(sm);
        assertTrue(sm.updateEntry("127.0.0.1"));
        assertEquals(sm.getEntries().size(), 1);
        sm.set(s);

        sm = StateModel.get("picard", s);
        assertTrue(sm.updateEntry("10.0.0.1", new DateTime().minusDays(1)));
        sm.set(s);

        sm = StateModel.get("picard", s);
        assertEquals(sm.getEntries().size(), 2);
        sm.pruneState(43200L);
        sm.set(s);
        sm = StateModel.get("picard", s);
        assertEquals(sm.getEntries().size(), 1);

        s.done();
    }
}
