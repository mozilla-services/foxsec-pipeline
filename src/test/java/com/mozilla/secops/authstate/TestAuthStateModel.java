package com.mozilla.secops.authstate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import org.joda.time.DateTime;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class TestAuthStateModel {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  private void testEnv() {
    environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
    environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
    environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
    environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
  }

  public TestAuthStateModel() {}

  @Test
  public void AuthStateModelTest() throws Exception {
    testEnv();
    State s = new State(new DatastoreStateInterface("authprofile", "teststatemodel"));
    StateCursor c;
    s.initialize();

    c = s.newCursor();
    assertNull(AuthStateModel.get("nonexist", c));
    c.commit();

    AuthStateModel sm = new AuthStateModel("riker");
    assertNotNull(sm);
    c = s.newCursor();
    sm.set(c);

    c = s.newCursor();
    sm = AuthStateModel.get("riker", c);
    assertNotNull(sm);
    assertEquals(sm.getEntries().size(), 0);

    // Reuse existing cursor from previous step
    assertTrue(sm.updateEntry("127.0.0.1", 1.0, 1.0)); // Assert true for new address
    assertEquals(sm.getEntries().size(), 1);
    sm.set(c);

    c = s.newCursor();
    sm = AuthStateModel.get("riker", c);
    assertEquals(sm.getEntries().size(), 1);
    assertFalse(sm.updateEntry("127.0.0.1", 1.0, 1.0)); // Assert false for update existing
    sm.set(c);

    c = s.newCursor();
    assertTrue(sm.updateEntry("10.0.0.1", 44.0, 44.0));
    assertEquals(sm.getEntries().size(), 2);
    sm.set(c);
    c = s.newCursor();
    sm = AuthStateModel.get("riker", c);
    assertEquals(sm.getEntries().size(), 2);
    c.commit();

    sm = new AuthStateModel("picard");
    assertNotNull(sm);
    assertTrue(sm.updateEntry("127.0.0.1", 1.0, 1.0));
    assertEquals(sm.getEntries().size(), 1);
    c = s.newCursor();
    sm.set(c);

    c = s.newCursor();
    sm = AuthStateModel.get("picard", c);
    assertTrue(sm.updateEntry("10.0.0.1", new DateTime().minusDays(1), 44.0, 44.0));
    sm.set(c);

    c = s.newCursor();
    sm = AuthStateModel.get("picard", c);
    assertEquals(sm.getEntries().size(), 2);
    sm.pruneState(43200L);
    sm.set(c);
    c = s.newCursor();
    sm = AuthStateModel.get("picard", c);
    assertEquals(sm.getEntries().size(), 1);
    c.commit();

    s.done();
  }
}
