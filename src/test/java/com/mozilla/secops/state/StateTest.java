package com.mozilla.secops.state;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Test;
import org.junit.Rule;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.util.Collection;
import java.util.Arrays;

@RunWith(Parameterized.class)
public class StateTest {
    @Rule
    public final EnvironmentVariables environmentVariables
        = new EnvironmentVariables();

    private void testEnv() {
        environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
        environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
        environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
        environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
    }

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
            { new SimpleStateInterface() },
            { new MemcachedStateInterface("127.0.0.1") },
            { new DatastoreStateInterface("test") }
        });
    }

    private StateInterface si;

    public StateTest(StateInterface si) {
        this.si = si;
    }

    @Test
    public void testStateConstruct() throws Exception {
        testEnv();
        State s = new State(si);
        assertNotNull(s);
        s.initialize();
    }

    @Test
    public void testStateSetGet() throws Exception {
        testEnv();
        State s = new State(si);
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
    public void testStateSetGetNoExist() throws Exception {
        testEnv();
        State s = new State(si);
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

    @Test(expected = StateException.class)
    public void testStateSetZeroLengthKey() throws Exception {
        testEnv();
        State s = new State(si);
        assertNotNull(s);
        s.initialize();
        StateTestClass t = new StateTestClass();
        assertNotNull(t);
        t.str = "test";
        s.set("", t);
    }

    @Test(expected = StateException.class)
    public void testStateGetZeroLengthKey() throws Exception {
        testEnv();
        State s = new State(si);
        assertNotNull(s);
        s.initialize();
        s.get("", StateTestClass.class);
    }
}
