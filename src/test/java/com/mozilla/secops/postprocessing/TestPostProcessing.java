package com.mozilla.secops.postprocessing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.Watchlist;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class TestPostProcessing {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  private void testEnv() throws Exception {
    environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
    environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
    environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
    environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
    clearState();
  }

  public TestPostProcessing() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  public void clearState() throws Exception {
    State state = new State(new DatastoreStateInterface("postprocessing", "testpostprocessing"));
    state.initialize();
    state.deleteAll();
    state.done();
  }

  private PostProcessing.PostProcessingOptions getTestOptions() {
    PostProcessing.PostProcessingOptions ret =
        PipelineOptionsFactory.as(PostProcessing.PostProcessingOptions.class);
    ret.setWarningSeverityEmail("picard@enterprise.com");
    ret.setCriticalSeverityEmail("pagerduty@enterprise.com");
    return ret;
  }

  private void addWatchlistEntries() throws Exception {
    StateCursor c;

    State is =
        new State(
            new DatastoreStateInterface(
                Watchlist.watchlistIpKind, Watchlist.watchlistDatastoreNamespace));
    is.initialize();
    Watchlist.WatchlistEntry ipe = new Watchlist.WatchlistEntry();
    ipe.setType("ip");
    ipe.setObject("127.0.0.1");
    ipe.setSeverity(Alert.AlertSeverity.CRITICAL);
    ipe.setCreatedBy("picard");
    ipe.setExpiresAt(new DateTime());
    c = is.newCursor();
    c.set(ipe.getObject(), ipe);
    c.commit();
    is.done();

    State es =
        new State(
            new DatastoreStateInterface(
                Watchlist.watchlistEmailKind, Watchlist.watchlistDatastoreNamespace));
    es.initialize();
    Watchlist.WatchlistEntry emaile = new Watchlist.WatchlistEntry();
    emaile.setType("email");
    emaile.setObject("example@enterprise.com");
    emaile.setSeverity(Alert.AlertSeverity.WARNING);
    emaile.setCreatedBy("picard");
    emaile.setExpiresAt(new DateTime());
    c = es.newCursor();
    c.set(emaile.getObject(), emaile);
    c.commit();
    es.done();
  }

  @Test
  public void testWatchlistAnalyze() throws Exception {
    testEnv();
    addWatchlistEntries();

    PostProcessing.PostProcessingOptions options = getTestOptions();
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/watchlist_analyze_buffer1.txt"});
    options.setGenerateConfigurationTicksInterval(1);
    options.setGenerateConfigurationTicksMaximum(5L);
    PCollection<String> input =
        p.apply(
            "input",
            Input.compositeInputAdapter(options, PostProcessing.buildConfigurationTick(options)));

    PCollection<Alert> res = PostProcessing.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              int emailCnt = 0;
              int ipCnt = 0;
              int cfgTickCnt = 0;
              for (Alert a : results) {
                if (a.getMetadataValue("category").equals("watchlist")) {
                  assertEquals("postprocessing", a.getCategory());
                  assertEquals(
                      "0e555555-8df8-4b3d-92dd-24e0e5248534", a.getMetadataValue("source_alert"));
                  if (a.getMetadataValue("matched_type").equals("email")) {
                    emailCnt++;
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertEquals("email", a.getMetadataValue("matched_type"));
                    assertEquals("username", a.getMetadataValue("matched_metadata_key"));
                    assertEquals(
                        "picard@enterprise.com", a.getMetadataValue("notify_email_direct"));
                    assertEquals(
                        "example@enterprise.com", a.getMetadataValue("matched_metadata_value"));
                  } else if (a.getMetadataValue("matched_type").equals("ip")) {
                    ipCnt++;
                    assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                    assertEquals(
                        "pagerduty@enterprise.com", a.getMetadataValue("notify_email_direct"));
                    assertEquals("ip", a.getMetadataValue("matched_type"));
                    assertEquals("sourceaddress", a.getMetadataValue("matched_metadata_key"));
                    assertEquals("127.0.0.1", a.getMetadataValue("matched_metadata_value"));
                  }
                } else if (a.getMetadataValue("category").equals("cfgtick")) {
                  cfgTickCnt++;
                  assertEquals("postprocessing-cfgtick", a.getCategory());
                  assertEquals(
                      "./target/test-classes/testdata/watchlist_analyze_buffer1.txt",
                      a.getMetadataValue("inputFile"));
                  assertEquals("5", a.getMetadataValue("generateConfigurationTicksMaximum"));
                } else {
                  fail("unexpected category");
                }
              }

              assertEquals(5, cfgTickCnt);
              assertEquals(2, emailCnt);
              assertEquals(1, ipCnt);

              return null;
            });

    p.run().waitUntilFinish();
  }
}
