package com.mozilla.secops.postprocessing;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.mozilla.secops.Watchlist;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import org.apache.beam.sdk.PipelineResult;
import org.apache.beam.sdk.metrics.DistributionResult;
import org.apache.beam.sdk.metrics.MetricNameFilter;
import org.apache.beam.sdk.metrics.MetricResult;
import org.apache.beam.sdk.metrics.MetricsFilter;
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
    StateCursor<Watchlist.WatchlistEntry> c;

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
    c = is.newCursor(Watchlist.WatchlistEntry.class, true);
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
    c = es.newCursor(Watchlist.WatchlistEntry.class, true);
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
                if (a.getMetadataValue(AlertMeta.Key.CATEGORY).equals("watchlist")) {
                  assertEquals("postprocessing", a.getCategory());
                  assertEquals(
                      "0e555555-8df8-4b3d-92dd-24e0e5248534",
                      a.getMetadataValue(AlertMeta.Key.SOURCE_ALERT));
                  if (a.getMetadataValue(AlertMeta.Key.MATCHED_TYPE).equals("email")) {
                    emailCnt++;
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertEquals("email", a.getMetadataValue(AlertMeta.Key.MATCHED_TYPE));
                    assertEquals(
                        "identity_key", a.getMetadataValue(AlertMeta.Key.MATCHED_METADATA_KEY));
                    assertEquals(
                        "picard@enterprise.com",
                        a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                    assertEquals(
                        "example@enterprise.com",
                        a.getMetadataValue(AlertMeta.Key.MATCHED_METADATA_VALUE));
                  } else if (a.getMetadataValue(AlertMeta.Key.MATCHED_TYPE).equals("ip")) {
                    ipCnt++;
                    assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                    assertEquals(
                        "pagerduty@enterprise.com",
                        a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                    assertEquals("ip", a.getMetadataValue(AlertMeta.Key.MATCHED_TYPE));
                    assertEquals(
                        "sourceaddress", a.getMetadataValue(AlertMeta.Key.MATCHED_METADATA_KEY));
                    assertEquals(
                        "127.0.0.1", a.getMetadataValue(AlertMeta.Key.MATCHED_METADATA_VALUE));
                  }
                } else if (a.getMetadataValue(AlertMeta.Key.CATEGORY).equals("cfgtick")) {
                  cfgTickCnt++;
                  assertEquals("postprocessing-cfgtick", a.getCategory());
                  assertEquals(
                      "./target/test-classes/testdata/watchlist_analyze_buffer1.txt",
                      a.getCustomMetadataValue("inputFile"));
                  assertEquals("5", a.getCustomMetadataValue("generateConfigurationTicksMaximum"));
                } else {
                  fail("unexpected category");
                }
              }

              assertEquals(5, cfgTickCnt);
              assertEquals(2, emailCnt);
              assertEquals(1, ipCnt);

              return null;
            });

    PipelineResult pResult = p.run();
    pResult.waitUntilFinish();

    Iterable<MetricResult<DistributionResult>> alertTimes =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            PostProcessing.METRICS_NAMESPACE,
                            PostProcessing.WATCHLIST_ALERT_PROCESSING_TIME_METRIC))
                    .build())
            .getDistributions();

    for (MetricResult<DistributionResult> x : alertTimes) {
      DistributionResult dr = x.getCommitted();
      assertEquals(3, dr.getCount());
    }
  }

  @Test
  public void testAlertSummary() throws Exception {
    PostProcessing.PostProcessingOptions options = getTestOptions();
    options.setEnableWatchlistAnalysis(false);
    options.setEnableAlertSummaryAnalysis(true);
    options.setAlertSummaryAnalysisThresholds(new String[] {"*:50:50:1"});
    options.setUseEventTimestamp(true);
    options.setInputFile(new String[] {"./target/test-classes/testdata/alertsummary_buffer1.txt"});
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
              int globalSmallIncreaseCount = 0;
              int globalLargeIncreaseCount = 0;
              int globalSmallDecreaseCount = 0;
              int total = 0;
              for (Alert a : results) {
                total++;
                if (a.getSummary()
                    .contains(
                        "increase, 1 alerts -> 10 alerts over previous 15m using criteria *:50:50:1")) {
                  assertEquals("*:50:50:1", a.getMetadataValue(AlertMeta.Key.THRESHOLD));
                  assertEquals("2020-01-01T00:00:00.000Z", a.getMetadataValue(AlertMeta.Key.START));
                  assertEquals("2020-01-01T00:29:59.999Z", a.getMetadataValue(AlertMeta.Key.END));
                  assertEquals(
                      "picard@enterprise.com",
                      a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  globalSmallIncreaseCount++;
                } else if (a.getSummary()
                    .contains(
                        "decrease, 5 alerts -> 1 alerts over previous 15m using criteria *:50:50:1")) {
                  assertEquals("*:50:50:1", a.getMetadataValue(AlertMeta.Key.THRESHOLD));
                  assertEquals("2020-01-01T00:45:00.000Z", a.getMetadataValue(AlertMeta.Key.START));
                  assertEquals("2020-01-01T01:14:59.999Z", a.getMetadataValue(AlertMeta.Key.END));
                  assertEquals(
                      "picard@enterprise.com",
                      a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  globalSmallDecreaseCount++;
                } else if (a.getSummary()
                    .contains(
                        "increase, 16 alerts -> 41 alerts over previous 1h using "
                            + "criteria *:50:50:1")) {
                  assertEquals("*:50:50:1", a.getMetadataValue(AlertMeta.Key.THRESHOLD));
                  assertEquals("2020-01-01T00:00:00.000Z", a.getMetadataValue(AlertMeta.Key.START));
                  assertEquals("2020-01-01T01:59:59.999Z", a.getMetadataValue(AlertMeta.Key.END));
                  assertEquals(
                      "picard@enterprise.com",
                      a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  globalLargeIncreaseCount++;
                } else {
                  // Otherwise, a configuration tick
                  assertEquals(
                      "Analyze alerts across windows to identify threshold violations and anomalies. "
                          + "Applied criteria, [*:50:50:1].",
                      a.getCustomMetadataValue("heuristic_AlertSummary"));
                }
              }
              assertEquals(1, globalSmallIncreaseCount);
              assertEquals(1, globalSmallDecreaseCount);
              assertEquals(1, globalLargeIncreaseCount);
              assertEquals(8, total);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testAlertSummaryClassifiers() throws Exception {
    PostProcessing.PostProcessingOptions options = getTestOptions();
    options.setEnableWatchlistAnalysis(false);
    options.setEnableAlertSummaryAnalysis(true);
    options.setAlertSummaryAnalysisThresholds(
        new String[] {
          "testsdec:50:50:1",
          "authprofile:50:50:1",
          "*:1:1:5000",
          "testsdec-authprofile:50:50:1",
          "testsdec-authprofile-state_analyze:50:50:1"
        });
    options.setUseEventTimestamp(true);
    options.setInputFile(new String[] {"./target/test-classes/testdata/alertsummary_buffer1.txt"});
    PCollection<String> input =
        p.apply(
            "input",
            Input.compositeInputAdapter(options, PostProcessing.buildConfigurationTick(options)));

    PCollection<Alert> res = PostProcessing.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              int total = 0;
              for (Alert a : results) {
                total++;
                if (a.getSummary()
                    .equals(
                        "alert increase, 5 alerts -> 41 alerts over previous 1h using "
                            + "criteria authprofile:50:50:1")) {
                  assertEquals(
                      a.getPayload(),
                      "An increase in alerts was observed that triggered a configured "
                          + "threshold.\n\nThe alert count was 41 over the previous 1h, and "
                          + "was 5 during the 1h prior.\n\nThe threshold that matched was a "
                          + "50 percent increase for all alerts for service testsdec of cate"
                          + "gory authprofile with at least 1 alert(s) present.\n");
                } else if (a.getSummary()
                    .equals(
                        "alert decrease, 5 alerts -> 1 alerts over previous 15m using "
                            + "criteria testsdec-authprofile-state_analyze:50:50:1")) {
                  assertEquals(
                      a.getPayload(),
                      "A decrease in alerts was observed that triggered a configured "
                          + "threshold.\n\nThe alert count was 1 over the previous 15m, and"
                          + " was 5 during the 15m prior.\n\nThe threshold that matched was "
                          + "a 50 percent decrease for all alerts for service testsdec of ca"
                          + "tegory authprofile and subcategory state_analyze with at least "
                          + "1 alert(s) present.\n");
                }
                assertThat(
                    a.getSummary(),
                    anyOf(
                        equalTo(
                            "alert increase, 5 alerts -> 41 alerts over previous 1h using "
                                + "criteria testsdec:50:50:1"),
                        equalTo(
                            "alert increase, 5 alerts -> 41 alerts over previous 1h using "
                                + "criteria testsdec-authprofile:50:50:1"),
                        equalTo(
                            "alert increase, 1 alerts -> 10 alerts over previous 15m using "
                                + "criteria authprofile:50:50:1"),
                        equalTo(
                            "alert decrease, 5 alerts -> 1 alerts over previous 15m using "
                                + "criteria testsdec:50:50:1"),
                        equalTo(
                            "alert decrease, 5 alerts -> 1 alerts over previous 15m using "
                                + "criteria authprofile:50:50:1"),
                        equalTo(
                            "alert decrease, 5 alerts -> 1 alerts over previous 15m using "
                                + "criteria testsdec-authprofile:50:50:1"),
                        equalTo(
                            "alert decrease, 5 alerts -> 1 alerts over previous 15m using "
                                + "criteria testsdec-authprofile-state_analyze:50:50:1"),
                        equalTo(
                            "alert increase, 5 alerts -> 41 alerts over previous 1h using "
                                + "criteria testsdec-authprofile-state_analyze:50:50:1"),
                        equalTo(
                            "alert increase, 16 alerts -> 41 alerts over previous 1h using "
                                + "criteria authprofile:50:50:1")));
                assertEquals(
                    "picard@enterprise.com", a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
              }
              assertEquals(9, total);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
