package com.mozilla.secops.gatekeeper;

import static org.junit.Assert.*;

import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.ParserTest;
import java.io.IOException;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.ParDo;
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

  private GatekeeperOptions getBaseTestOptions() {
    GatekeeperOptions opts = PipelineOptionsFactory.as(GatekeeperOptions.class);
    opts.setUseEventTimestamp(true);
    opts.setMonitoredResourceIndicator("gatekeeper-test");
    opts.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    opts.setOutputIprepd("http://127.0.0.1:8080");
    opts.setOutputIprepdApikey("test");
    return opts;
  }

  public TestGatekeeper() {}

  @Test
  public void gatekeeperNoFiltersTest() throws Exception {
    TestStream<String> s = getTestStream();
    GatekeeperOptions opts = getBaseTestOptions();

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    alerts.apply(ParDo.of(new AlertFormatter(opts))).apply(OutputOptions.compositeOutput(opts));

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(22L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                if (a.getCategory().equals("gatekeeper:aws")) {
                  assertTrue(
                      a.getSummary().startsWith("Suspicious activity detected in AWS account"));
                  assertEquals("967921969016", a.getMetadataValue("aws account"));
                  assertEquals("us-west-2", a.getMetadataValue("aws region"));
                } else if (a.getCategory().equals("gatekeeper:gcp")) {
                  assertTrue(a.getSummary().startsWith("Suspicious activity detected in GCP org"));
                  assertEquals("883576422677", a.getMetadataValue("project number"));
                  assertEquals("audit_log", a.getMetadataValue("indicator"));
                  assertEquals("persistence", a.getMetadataValue("technique"));
                  assertEquals("iam_anomalous_grant", a.getMetadataValue("ruleName"));
                } else {
                  fail(String.format("unexpected alert category type: %s", a.getCategory()));
                }
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperIgnoreAllETDTest() throws Exception {
    TestStream<String> s = getTestStream();
    GatekeeperOptions opts = getBaseTestOptions();
    opts.setIgnoreETDFindingRuleRegex(new String[] {".+"});

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    alerts.apply(ParDo.of(new AlertFormatter(opts))).apply(OutputOptions.compositeOutput(opts));

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(19L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                assertEquals("gatekeeper:aws", a.getCategory());
                assertTrue(
                    a.getSummary().startsWith("Suspicious activity detected in AWS account"));
                assertEquals("967921969016", a.getMetadataValue("aws account"));
                assertEquals("us-west-2", a.getMetadataValue("aws region"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperIgnoreAllGDTest() throws Exception {
    TestStream<String> s = getTestStream();
    GatekeeperOptions opts = getBaseTestOptions();
    opts.setIgnoreGDFindingTypeRegex(new String[] {".+"});

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    alerts.apply(ParDo.of(new AlertFormatter(opts))).apply(OutputOptions.compositeOutput(opts));

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(3L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                assertEquals("gatekeeper:gcp", a.getCategory());
                assertTrue(a.getSummary().startsWith("Suspicious activity detected in GCP org"));
                assertEquals("883576422677", a.getMetadataValue("project number"));
                assertEquals("audit_log", a.getMetadataValue("indicator"));
                assertEquals("persistence", a.getMetadataValue("technique"));
                assertEquals("iam_anomalous_grant", a.getMetadataValue("ruleName"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void gatekeeperIgnoreSomeGDTest() throws Exception {
    TestStream<String> s = getTestStream();
    GatekeeperOptions opts = getBaseTestOptions();
    opts.setIgnoreGDFindingTypeRegex(new String[] {"Recon:EC2.+"});

    PCollection<Alert> alerts = GatekeeperPipeline.executePipeline(p, p.apply(s), opts);

    alerts.apply(ParDo.of(new AlertFormatter(opts))).apply(OutputOptions.compositeOutput(opts));

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(21L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertNotNull(a.getCategory());
                if (a.getCategory().equals("gatekeeper:aws")) {
                  assertFalse(a.getMetadataValue("finding type").contains("Recon:EC2"));
                }
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
