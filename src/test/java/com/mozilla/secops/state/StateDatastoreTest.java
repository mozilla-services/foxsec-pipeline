package com.mozilla.secops.state;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import org.junit.Rule;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class StateDatastoreTest {
    public StateDatastoreTest() {
    }

    @Rule
    public final EnvironmentVariables environmentVariables
        = new EnvironmentVariables();

    private void testEnv() {
        environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
        environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
        environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
        environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
    }

    @Test
    public void testStateConstruct() throws Exception {
        testEnv();
        State s = new State(new DatastoreStateInterface("test"));
        assertNotNull(s);
        s.initialize();
    }

    @Test
    public void testSimpleStateSetGet() throws Exception {
        testEnv();
        State s = new State(new DatastoreStateInterface("test"));
        assertNotNull(s);
        s.initialize();
        StateTestClass t = new StateTestClass();
        assertNotNull(t);
        t.str = "test";
        s.set("testing", t);
        t = s.get("testing", StateTestClass.class);
        assertNotNull(t);
        assertEquals("test", t.str);
    }

    @Test
    public void testSimpleStateSetGetNoExist() throws Exception {
        testEnv();
        State s = new State(new DatastoreStateInterface("test"));
        assertNotNull(s);
        s.initialize();
        StateTestClass t = new StateTestClass();
        assertNotNull(t);
        t.str = "test";
        s.set("testing", t);
        t = s.get("testing", StateTestClass.class);
        assertNotNull(t);
        assertEquals("test", t.str);

        assertNull(s.get("nonexist", StateTestClass.class));
    }
}
