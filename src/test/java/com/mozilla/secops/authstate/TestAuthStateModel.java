package com.mozilla.secops.authstate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import java.util.AbstractMap;
import java.util.ArrayList;
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
  public void authStateModelTimeSortedTest() throws Exception {
    AuthStateModel sm = new AuthStateModel("riker");
    sm.updateEntry("127.0.0.4", new DateTime(4L), 4.0, 4.0);
    sm.updateEntry("127.0.0.3", new DateTime(3L), 3.0, 3.0);
    sm.updateEntry("127.0.0.1", new DateTime(1L), 1.0, 1.0);
    sm.updateEntry("127.0.0.2", new DateTime(2L), 2.0, 2.0);
    ArrayList<AbstractMap.SimpleEntry<String, AuthStateModel.ModelEntry>> ret =
        sm.timeSortedEntries();
    assertEquals(4, ret.size());
    assertEquals("127.0.0.1", ret.get(0).getKey());
    assertEquals(1L, ret.get(0).getValue().getTimestamp().getMillis());
    assertEquals("127.0.0.2", ret.get(1).getKey());
    assertEquals(2L, ret.get(1).getValue().getTimestamp().getMillis());
    assertEquals("127.0.0.3", ret.get(2).getKey());
    assertEquals(3L, ret.get(2).getValue().getTimestamp().getMillis());
    assertEquals("127.0.0.4", ret.get(3).getKey());
    assertEquals(4L, ret.get(3).getValue().getTimestamp().getMillis());
  }

  @Test
  public void authStateModelTest() throws Exception {
    testEnv();
    State s = new State(new DatastoreStateInterface("authprofile", "teststatemodel"));
    StateCursor<AuthStateModel> c;
    s.initialize();

    c = s.newCursor(AuthStateModel.class, true);
    assertNull(AuthStateModel.get("nonexist", c, new PruningStrategyEntryAge()));
    c.commit();

    AuthStateModel sm = new AuthStateModel("riker");
    assertNotNull(sm);
    c = s.newCursor(AuthStateModel.class, true);
    sm.set(c, new PruningStrategyEntryAge());

    c = s.newCursor(AuthStateModel.class, true);
    sm = AuthStateModel.get("riker", c, new PruningStrategyEntryAge());
    assertNotNull(sm);
    assertEquals(sm.getEntries().size(), 0);

    // Reuse existing cursor from previous step
    assertTrue(sm.updateEntry("127.0.0.1", 1.0, 1.0)); // Assert true for new address
    assertEquals(sm.getEntries().size(), 1);
    sm.set(c, new PruningStrategyEntryAge());

    c = s.newCursor(AuthStateModel.class, true);
    sm = AuthStateModel.get("riker", c, new PruningStrategyEntryAge());
    assertEquals(sm.getEntries().size(), 1);
    assertFalse(sm.updateEntry("127.0.0.1", 1.0, 1.0)); // Assert false for update existing
    sm.set(c, new PruningStrategyEntryAge());

    c = s.newCursor(AuthStateModel.class, true);
    assertTrue(sm.updateEntry("10.0.0.1", 44.0, 44.0));
    assertEquals(sm.getEntries().size(), 2);
    sm.set(c, new PruningStrategyEntryAge());
    c = s.newCursor(AuthStateModel.class, true);
    sm = AuthStateModel.get("riker", c, new PruningStrategyEntryAge());
    assertEquals(sm.getEntries().size(), 2);
    c.commit();

    sm = new AuthStateModel("picard");
    assertNotNull(sm);
    assertTrue(sm.updateEntry("127.0.0.1", 1.0, 1.0));
    assertEquals(sm.getEntries().size(), 1);
    c = s.newCursor(AuthStateModel.class, true);
    sm.set(c, new PruningStrategyEntryAge());

    c = s.newCursor(AuthStateModel.class, true);
    sm = AuthStateModel.get("picard", c, new PruningStrategyEntryAge());
    assertTrue(sm.updateEntry("10.0.0.1", new DateTime().minusDays(1), 44.0, 44.0));
    sm.set(c, new PruningStrategyEntryAge());

    c = s.newCursor(AuthStateModel.class, true);
    sm = AuthStateModel.get("picard", c, new PruningStrategyEntryAge());
    assertEquals(sm.getEntries().size(), 2);
    sm.set(c, new PruningStrategyEntryAge());
    c = s.newCursor(AuthStateModel.class, true);
    PruningStrategyEntryAge ps = new PruningStrategyEntryAge();
    ps.setEntryAgePruningSeconds(43200L);
    sm = AuthStateModel.get("picard", c, ps);
    assertEquals(sm.getEntries().size(), 1);
    c.commit();

    c = s.newCursor(AuthStateModel.class, true);
    sm = new AuthStateModel("laforge");
    assertTrue(sm.updateEntry("127.0.0.1", new DateTime().minusHours(1), 1.0, 1.0));
    assertFalse(sm.updateEntry("127.0.0.1", new DateTime().minusHours(1), 1.0, 1.0));
    assertTrue(sm.updateEntry("127.0.0.2", 1.0, 1.0));
    assertEquals(2, sm.getEntries().size());
    sm.set(c, new PruningStrategyLatest());
    c = s.newCursor(AuthStateModel.class, true);
    sm = AuthStateModel.get("laforge", c, new PruningStrategyLatest());
    assertEquals(1, sm.getEntries().size());
    // Updating should be true, since 127.0.0.1 will have been removed
    assertTrue(sm.updateEntry("127.0.0.1", 1.0, 1.0));
    c.commit();

    s.done();
  }
}
