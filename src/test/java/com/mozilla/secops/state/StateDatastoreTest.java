package com.mozilla.secops.state;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.rules.ExpectedException;

public class StateDatastoreTest {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  @Rule public ExpectedException expectEx = ExpectedException.none();

  private void testEnv() {
    environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
    environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
    environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
    environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
  }

  @Test
  public void testStateGetSetConcurrent() throws Exception {
    expectEx.expect(StateException.class);
    expectEx.expectMessage("too much contention on these datastore entities. please try again.");

    testEnv();
    State s = new State(new DatastoreStateInterface("test", "statetest"));
    assertNotNull(s);
    s.initialize();

    StateCursor<StateTestClass> c1 = s.newCursor(StateTestClass.class, true);
    StateCursor<StateTestClass> c2 = s.newCursor(StateTestClass.class, true);
    assertNotNull(c1);
    assertNotNull(c2);

    StateTestClass t = new StateTestClass();
    assertNotNull(t);

    t.str = "test";
    c1.set("testing", t);
    c1.commit();

    c1 = s.newCursor(StateTestClass.class, true);
    t = c1.get("testing");
    assertNotNull(t);
    assertEquals("test", t.str);

    StateTestClass t2 = c2.get("testing");
    assertNotNull(t2);
    assertEquals("test", t2.str);

    t2.str = "test2";
    c2.set("testing", t2);
    c2.commit();

    t.str = "changed";
    c1.set("testing", t);
    c1.commit();
  }
}
