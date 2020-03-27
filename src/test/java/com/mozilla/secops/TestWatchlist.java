package com.mozilla.secops;

import static org.junit.Assert.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import java.util.ArrayList;
import org.joda.time.DateTime;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class TestWatchlist {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  private void testEnv() {
    environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
    environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
    environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
    environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
  }

  public TestWatchlist() {}

  @Test
  public void watchlistTest() throws Exception {
    testEnv();
    State is =
        new State(
            new DatastoreStateInterface(
                Watchlist.watchlistIpKind, Watchlist.watchlistDatastoreNamespace));
    is.initialize();
    is.deleteAll();
    State es =
        new State(
            new DatastoreStateInterface(
                Watchlist.watchlistEmailKind, Watchlist.watchlistDatastoreNamespace));
    es.initialize();
    es.deleteAll();
    StateCursor<Watchlist.WatchlistEntry> c;

    Watchlist wl = new Watchlist();

    assertEquals(wl.getWatchedEmails().length, 0);
    assertEquals(wl.getWatchedIPs().length, 0);

    // Add IP watchlist entry
    Watchlist.WatchlistEntry ipe = new Watchlist.WatchlistEntry();
    ipe.setType(Watchlist.watchlistIpKind);
    ipe.setObject("127.0.0.1");
    ipe.setSeverity(Alert.AlertSeverity.INFORMATIONAL);
    ipe.setCreatedBy("picard");
    ipe.setExpiresAt(new DateTime());

    c = is.newCursor(Watchlist.WatchlistEntry.class, true);
    c.set(ipe.getObject(), ipe);
    c.commit();

    Watchlist.WatchlistEntry[] ips = wl.getWatchedIPs();
    assertEquals(1, ips.length);
    assertEquals(ips[0], ipe);

    ArrayList<String> buf = new ArrayList<>();
    buf.add("127.0.0.1");
    ArrayList<Watchlist.WatchlistEntry> entries =
        wl.getWatchlistEntries(Watchlist.watchlistIpKind, buf);
    assertNotNull(entries);
    assertEquals(entries.get(0), ipe);

    // Add email watchlist entries
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    String emailOneBuf =
        "{\"created_by\": \"picard\", \"type\": \"email\", \"object\": \"example@enterprise.com\","
            + "\"expires_at\": \"2020-01-07T02:45:23.000Z\", \"severity\": \"info\"}";
    Watchlist.WatchlistEntry emailOne =
        mapper.readValue(emailOneBuf, Watchlist.WatchlistEntry.class);
    Watchlist.WatchlistEntry emailTwo = new Watchlist.WatchlistEntry();
    emailTwo.setType("email");
    emailTwo.setObject("picardTwo@enterprise.com");
    emailTwo.setSeverity(Alert.AlertSeverity.WARNING);
    emailTwo.setCreatedBy("picard");
    emailTwo.setExpiresAt(new DateTime());

    c = es.newCursor(Watchlist.WatchlistEntry.class, true);
    c.set(emailOne.getObject(), emailOne);
    c.commit();

    buf = new ArrayList<>();
    buf.add("example@enterprise.com");
    entries = wl.getWatchlistEntries(Watchlist.watchlistEmailKind, buf);
    assertNotNull(entries);
    assertEquals(entries.get(0), emailOne);

    c = es.newCursor(Watchlist.WatchlistEntry.class, true);
    c.set(emailTwo.getObject(), emailTwo);
    c.commit();

    Watchlist.WatchlistEntry[] emails = wl.getWatchedEmails();
    assertEquals(2, emails.length);

    int cnt = 0;
    for (Watchlist.WatchlistEntry email : emails) {
      if (email.getObject().equals(emailOne.getObject())) {
        assertEquals(emailOne, email);
        cnt++;
      }
      if (email.getObject().equals(emailTwo.getObject())) {
        assertEquals(emailTwo, email);
        cnt++;
      }
    }
    assertEquals(2, cnt);

    is.done();
    es.done();
  }
}
