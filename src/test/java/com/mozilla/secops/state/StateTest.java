package com.mozilla.secops.state;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class StateTest {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  private void testEnv() {
    environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
    environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
    environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
    environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
  }

  @Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList(
        new Object[][] {
          {new MemcachedStateInterface("127.0.0.1", 11211)},
          {new DatastoreStateInterface("test", "statetest")}
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
    StateCursor<StateTestClass> c = s.newCursor(StateTestClass.class, false);
    assertNotNull(c);

    StateTestClass t = new StateTestClass();
    assertNotNull(t);

    t.str = "test";
    c.set("testing", t);

    t = c.get("testing");
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

    StateCursor<StateTestClass> c = s.newCursor(StateTestClass.class, false);
    c.set("testing", t);
    t = c.get("testing");
    assertNotNull(t);
    assertEquals("test", t.str);

    c = s.newCursor(StateTestClass.class, false);
    assertNull(c.get("nonexist"));
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
    StateCursor<StateTestClass> c = s.newCursor(StateTestClass.class, false);
    c.set("", t);
  }

  @Test(expected = StateException.class)
  public void testStateGetZeroLengthKey() throws Exception {
    testEnv();
    State s = new State(si);
    assertNotNull(s);
    s.initialize();
    StateCursor<StateTestClass> c = s.newCursor(StateTestClass.class, false);
    c.get("");
  }
}
