package com.mozilla.secops.postprocessing;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.mozilla.secops.Watchlist;
import com.mozilla.secops.alert.Alert;
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
                    assertEquals("identity_key", a.getMetadataValue("matched_metadata_key"));
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
                  assertEquals("*:50:50:1", a.getMetadataValue("threshold"));
                  assertEquals("2020-01-01T00:00:00.000Z", a.getMetadataValue("start"));
                  assertEquals("2020-01-01T00:29:59.999Z", a.getMetadataValue("end"));
                  assertEquals("picard@enterprise.com", a.getMetadataValue("notify_email_direct"));
                  globalSmallIncreaseCount++;
                } else if (a.getSummary()
                    .contains(
                        "decrease, 5 alerts -> 1 alerts over previous 15m using criteria *:50:50:1")) {
                  assertEquals("*:50:50:1", a.getMetadataValue("threshold"));
                  assertEquals("2020-01-01T00:45:00.000Z", a.getMetadataValue("start"));
                  assertEquals("2020-01-01T01:14:59.999Z", a.getMetadataValue("end"));
                  assertEquals("picard@enterprise.com", a.getMetadataValue("notify_email_direct"));
                  globalSmallDecreaseCount++;
                } else if (a.getSummary()
                    .contains(
                        "increase, 16 alerts -> 41 alerts over previous 1h using "
                            + "criteria *:50:50:1")) {
                  assertEquals("*:50:50:1", a.getMetadataValue("threshold"));
                  assertEquals("2020-01-01T00:00:00.000Z", a.getMetadataValue("start"));
                  assertEquals("2020-01-01T01:59:59.999Z", a.getMetadataValue("end"));
                  assertEquals("picard@enterprise.com", a.getMetadataValue("notify_email_direct"));
                  globalLargeIncreaseCount++;
                } else {
                  // Otherwise, a configuration tick
                  assertEquals(
                      "Analyze alerts across windows to identify threshold violations and anomalies. "
                          + "Applied criteria, [*:50:50:1].",
                      a.getMetadataValue("heuristic_AlertSummary"));
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
                assertEquals("picard@enterprise.com", a.getMetadataValue("notify_email_direct"));
              }
              assertEquals(9, total);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
