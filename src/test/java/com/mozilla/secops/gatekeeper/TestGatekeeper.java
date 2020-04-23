package com.mozilla.secops.gatekeeper;

import static org.junit.Assert.*;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import java.io.IOException;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestGatekeeper {
  @Rule public final transient TestPipeline p = TestPipeline.create();

  private TestStream<String> getTestStream() throws IOException {
    String[] gd = TestUtil.getTestInputArray("/testdata/gatekeeper/guardduty-sample-findings.txt");
    String[] etd = TestUtil.getTestInputArray("/testdata/gatekeeper/etd-sample-findings.txt");
    return TestStream.create(StringUtf8Coder.of())
        .advanceWatermarkTo(new Instant(0L))
        .addElements(gd[0], Arrays.copyOfRange(gd, 1, gd.length))
        .advanceWatermarkTo(new Instant(180000L))
        .addElements(etd[0], Arrays.copyOfRange(etd, 1, etd.length))
        .advanceWatermarkToInfinity();
  }

  private GatekeeperPipeline.GatekeeperOptions getBaseTestOptions() {
    GatekeeperPipeline.GatekeeperOptions opts =
        PipelineOptionsFactory.as(GatekeeperPipeline.GatekeeperOptions.class);
    opts.setUseEventTimestamp(true);
    opts.setMonitoredResourceIndicator("gatekeeper-test");
    opts.setGuarddutyConfigPath("/testdata/guarddutyconfig.json");
    opts.setIdentityManagerPath("/testdata/identitymanager.json");
    return opts;
  }

  public TestGatekeeper() {}

  @Test
  public void gatekeeperNoFiltersTest() throws Exception {
    GatekeeperPipeline.GatekeeperOptions opts = getBaseTestOptions();
    // Set an empty guardduty config
    opts.setGuarddutyConfigPath("/testdata/guarddutyconfig-empty.json");
    opts.setInputFile(
        new String[] {
          "./target/test-classes/testdata/gatekeeper/guardduty-sample-findings-default.txt",
          "./target/test-classes/testdata/gatekeeper/etd-sample-findings.txt"
        });
    opts.setGenerateConfigurationTicksInterval(1);
    opts.setGenerateConfigurationTicksMaximum(5L);
    PCollection<String> input =
        p.apply(
            "input",
            Input.compositeInputAdapter(opts, GatekeeperPipeline.buildConfigurationTick(opts)));

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, input, opts);

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(27L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int findingUrlChecked = 0;
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                if (a.getCategory().equals("gatekeeper:aws")) {
                  assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                  assertTrue(
                      a.getSummary().startsWith("suspicious activity detected in aws account"));

                  assertEquals("123456789012", a.getMetadataValue(AlertMeta.Key.AWS_ACCOUNT_ID));
                  assertEquals("us-west-2", a.getMetadataValue(AlertMeta.Key.AWS_REGION));

                  assertNotNull(a.getMetadataValue(AlertMeta.Key.URL_TO_FINDING));
                  if (a.getMetadataValue(AlertMeta.Key.FINDING_ID)
                      .equals("36b59ed2edad8b965a0ee921052cb481")) {
                    findingUrlChecked++;
                    assertEquals(
                        "https://us-west-2.console.aws.amazon.com/guardduty/home?region=us-west-2#/findings?fId=36b59ed2edad8b965a0ee921052cb481",
                        a.getMetadataValue(AlertMeta.Key.URL_TO_FINDING));
                  }
                } else if (a.getCategory().equals("gatekeeper:gcp")) {
                  assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                  assertTrue(a.getSummary().startsWith("suspicious activity detected in gcp org"));
                  // the three project numbers in the sample data
                  assertTrue(
                      a.getMetadataValue(AlertMeta.Key.PROJECT_NUMBER).equals("123456789012")
                          || a.getMetadataValue(AlertMeta.Key.PROJECT_NUMBER).equals("123456785822")
                          || a.getMetadataValue(AlertMeta.Key.PROJECT_NUMBER)
                              .equals("123456789210"));
                  assertEquals("audit_log", a.getMetadataValue(AlertMeta.Key.INDICATOR));
                  assertEquals("persistence", a.getMetadataValue(AlertMeta.Key.TECHNIQUE));
                } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("cfgtick")) {
                  assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                  assertEquals("gatekeeper-cfgtick", a.getCategory());
                  assertEquals("5", a.getCustomMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alerts are generated based on events sent from AWS's Guardduty.",
                      a.getCustomMetadataValue("heuristic_GenerateGDAlerts"));
                  assertEquals(
                      "Alerts are generated based on events sent from GCP's Event Threat Detection.",
                      a.getCustomMetadataValue("heuristic_GenerateETDAlerts"));

                } else {
                  fail(String.format("unexpected alert category type: %s", a.getCategory()));
                }
              }
              assertEquals(findingUrlChecked, 1);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperIgnoreAllETDTest() throws Exception {
    TestStream<String> s = getTestStream();
    GatekeeperPipeline.GatekeeperOptions opts = getBaseTestOptions();
    opts.setIgnoreETDFindingRuleRegex(new String[] {".+"});

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(17L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                assertEquals("gatekeeper:aws", a.getCategory());
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperETDTest() throws Exception {
    TestStream<String> s = getTestStream();
    GatekeeperPipeline.GatekeeperOptions opts = getBaseTestOptions();
    opts.setGuarddutyConfigPath("/testdata/guarddutyconfig-ignore-all.json");

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(3L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                assertEquals("gatekeeper:gcp", a.getCategory());
                assertTrue(a.getSummary().startsWith("suspicious activity detected in gcp org"));
                // the three project numbers in the sample data
                assertTrue(
                    a.getMetadataValue(AlertMeta.Key.PROJECT_NUMBER).equals("123456789012")
                        || a.getMetadataValue(AlertMeta.Key.PROJECT_NUMBER).equals("123456785822")
                        || a.getMetadataValue(AlertMeta.Key.PROJECT_NUMBER).equals("123456789210"));
                assertEquals("audit_log", a.getMetadataValue(AlertMeta.Key.INDICATOR));
                assertEquals("persistence", a.getMetadataValue(AlertMeta.Key.TECHNIQUE));
                assertEquals("iam_anomalous_grant", a.getMetadataValue(AlertMeta.Key.RULE_NAME));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperGDTest() throws Exception {
    TestStream<String> s = getTestStream();
    GatekeeperPipeline.GatekeeperOptions opts = getBaseTestOptions();
    opts.setCriticalNotificationEmail("triage@example.com");

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(20L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int highCheck = 0;
              int lowCheck = 0;
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                if (a.getCategory().equals("gatekeeper:aws")) {
                  if (a.getMetadataValue(AlertMeta.Key.FINDING_TYPE).startsWith("Trojan")) {
                    highCheck++;
                    assertEquals(
                        "triage@example.com",
                        a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                    assertEquals("high", a.getMetadataValue(AlertMeta.Key.ALERT_HANDLING_SEVERITY));
                  } else if (a.getMetadataValue(AlertMeta.Key.FINDING_TYPE)
                      .startsWith("Backdoor")) {
                    highCheck++;
                    assertEquals(
                        "triage@example.com",
                        a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                    assertEquals("high", a.getMetadataValue(AlertMeta.Key.ALERT_HANDLING_SEVERITY));
                  } else if (a.getMetadataValue(AlertMeta.Key.AWS_ACCOUNT_ID).equals("999999999")) {
                    highCheck++;
                    assertEquals(
                        "triage@example.com",
                        a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                    assertEquals("high", a.getMetadataValue(AlertMeta.Key.ALERT_HANDLING_SEVERITY));
                  } else {
                    lowCheck++;
                    assertNull(a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                    assertEquals("low", a.getMetadataValue(AlertMeta.Key.ALERT_HANDLING_SEVERITY));
                  }
                }
              }
              assertEquals(6, highCheck);
              assertEquals(11, lowCheck);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperSuppressRepeatedGDFindingsOneInstant() throws Exception {
    String[] gd =
        TestUtil.getTestInputArray(
            "/testdata/gatekeeper/guardduty-sample-findings-with-duplicates.txt");

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(gd[0], Arrays.copyOfRange(gd, 1, gd.length))
            .advanceWatermarkToInfinity();
    GatekeeperPipeline.GatekeeperOptions opts = getBaseTestOptions();

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    // the sample data contains 5 findings in total, 2 share one id, 3 share another.
    // if all of these findings are processed within the default suppression window (15 mins) we
    // should get 2 alerts
    PAssert.that(alerts.apply(Count.globally())).containsInAnyOrder(2L);

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperSuppressRepeatedETDFindingsOneInstant() throws Exception {
    String[] gd =
        TestUtil.getTestInputArray("/testdata/gatekeeper/etd-sample-findings-with-duplicates.txt");

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(gd[0], Arrays.copyOfRange(gd, 1, gd.length))
            .advanceWatermarkToInfinity();
    GatekeeperPipeline.GatekeeperOptions opts = getBaseTestOptions();

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    // the sample data contains 5 findings in total, 2 share one project id, 3 share another.
    // if all of these findings are processed within the default suppression window (15 mins) we
    // should get 2 alerts
    PAssert.that(alerts.apply(Count.globally())).containsInAnyOrder(2L);

    p.run().waitUntilFinish();
  }
}
