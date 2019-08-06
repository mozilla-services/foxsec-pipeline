package com.mozilla.secops.amo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.TestIprepdIO;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.ParserTest;
import java.util.Arrays;
import org.apache.beam.sdk.PipelineResult;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.metrics.MetricNameFilter;
import org.apache.beam.sdk.metrics.MetricResult;
import org.apache.beam.sdk.metrics.MetricsFilter;
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

public class TestAmo {
  @Rule public final transient TestPipeline p = TestPipeline.create();

  private Amo.AmoOptions getTestOptions() {
    Amo.AmoOptions ret = PipelineOptionsFactory.as(Amo.AmoOptions.class);
    ret.setUseEventTimestamp(true);
    ret.setMonitoredResourceIndicator("test");
    ret.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    ret.setOutputIprepd("http://127.0.0.1:8080");
    ret.setOutputIprepdApikey("test");
    ret.setAccountMatchBanOnLogin(new String[] {"locutus.*"});
    ret.setAddonMatchCriteria(new String[] {".*test_submission.*:7500:7500"});
    // Reduce the required country match count for the IP login tests here
    ret.setAddonMultiIpLoginAlertOn(2);
    ret.setAddonMultiIpLoginAlertOnIp(2);
    return ret;
  }

  public TestAmo() {}

  @Test
  public void amoFxaAbuseNewVersionTest() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/amo_fxaacctabuse_newversion/block1.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/amo_fxaacctabuse_newversion/block2.txt");
    String[] eb3 = TestUtil.getTestInputArray("/testdata/amo_fxaacctabuse_newversion/block3.txt");

    // Simulate recorded bad reputation for email address
    TestIprepdIO.putReputation("email", "kurn@mozilla.com", 0);
    TestIprepdIO.putReputation("ip", "255.255.25.25", 25);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(180000L))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(190000L))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    PCollection<Alert> alerts = Amo.executePipeline(p, p.apply(s), getTestOptions());

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    alerts
        .apply(ParDo.of(new AlertFormatter(getTestOptions())))
        .apply(OutputOptions.compositeOutput(getTestOptions()));

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(10L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertEquals("amo", a.getCategory());
                if (a.getMetadataValue("amo_category")
                    .equals("fxa_account_abuse_new_version_login")) {
                  assertEquals("fxa_account_abuse_new_version_login", a.getNotifyMergeKey());
                  assertEquals("kurn@mozilla.com", a.getMetadataValue("email"));
                  assertEquals("255.255.25.26", a.getMetadataValue("sourceaddress"));
                  assertEquals(
                      "test login to amo from suspected fraudulent account, kurn@mozilla.com "
                          + "from 255.255.25.26",
                      a.getSummary());
                } else if (a.getMetadataValue("amo_category").equals("amo_restriction")) {
                  assertEquals("amo_restriction", a.getNotifyMergeKey());
                  assertEquals("kurn@mozilla.com", a.getMetadataValue("restricted_value"));
                  assertEquals(
                      "test request to amo from kurn@mozilla.com restricted based on reputation",
                      a.getSummary());
                } else if (a.getMetadataValue("amo_category")
                    .equals("fxa_account_abuse_new_version_login_banpattern")) {
                  assertEquals(
                      "fxa_account_abuse_new_version_login_banpattern", a.getNotifyMergeKey());
                  assertEquals("locutus@mozilla.com", a.getMetadataValue("email"));
                } else if (a.getMetadataValue("amo_category").equals("fxa_account_abuse_alias")) {
                  assertEquals("fxa_account_abuse_alias", a.getNotifyMergeKey());
                  assertEquals("6", a.getMetadataValue("count"));
                  assertEquals(
                      "test possible alias abuse in amo, laforge@mozilla.com has 6 aliases",
                      a.getSummary());
                } else if (a.getMetadataValue("amo_category").equals("amo_abuse_matched_addon")) {
                  assertEquals("amo_abuse_matched_addon", a.getNotifyMergeKey());
                  assertEquals("216.160.83.63", a.getMetadataValue("sourceaddress"));
                  assertEquals(
                      "00000000000000000000000000000000_test_submission.zip",
                      a.getMetadataValue("addon_filename"));
                  assertEquals("lwaxana@mozilla.com", a.getMetadataValue("email"));
                  assertEquals("7500", a.getMetadataValue("addon_size"));
                  assertEquals(
                      "test suspected malicious addon submission from 216.160.83.63, lwaxana@mozilla.com",
                      a.getSummary());
                } else if (a.getMetadataValue("amo_category").equals("amo_abuse_multi_match")) {
                  assertEquals("amo_abuse_multi_match", a.getNotifyMergeKey());
                  assertEquals("test addon abuse multi match, 10", a.getSummary());
                  assertEquals("10", a.getMetadataValue("count"));
                  assertEquals("x.xpi", a.getMetadataValue("addon_filename"));
                } else if (a.getMetadataValue("amo_category").equals("amo_abuse_multi_submit")) {
                  assertEquals("amo_abuse_multi_submit", a.getNotifyMergeKey());
                  assertEquals("test addon abuse multi submit, 10000 11", a.getSummary());
                  assertEquals("11", a.getMetadataValue("count"));
                } else if (a.getMetadataValue("amo_category").equals("amo_abuse_multi_ip_login")) {
                  assertEquals("amo_abuse_multi_ip_login", a.getNotifyMergeKey());
                  assertEquals(
                      "test addon abuse multi ip country login, sevenofnine@mozilla.net 2 countr"
                          + "ies, 2 source address",
                      a.getSummary());
                  assertEquals("2", a.getMetadataValue("count"));
                } else {
                  assertEquals("255.255.25.25", a.getMetadataValue("sourceaddress"));
                  if (a.getMetadataValue("addon_version") != null) {
                    assertEquals("fxa_account_abuse_new_version_submission", a.getNotifyMergeKey());
                    assertEquals("1.0.0", a.getMetadataValue("addon_version"));
                    assertEquals("0000001", a.getMetadataValue("addon_id"));
                    assertEquals(
                        "test addon submission from address associated with "
                            + "suspected fraudulent account, 255.255.25.25",
                        a.getSummary());
                  } else {
                    assertEquals("fxa_account_abuse_new_version_submission", a.getNotifyMergeKey());
                    assertNull(a.getMetadataValue("addon_version"));
                    assertNull(a.getMetadataValue("addon_id"));
                    assertEquals(
                        "test addon submission from address associated with "
                            + "suspected fraudulent account, 255.255.25.25",
                        a.getSummary());
                  }
                }
              }
              return null;
            });

    PipelineResult pResult = p.run();
    pResult.waitUntilFinish();

    Iterable<MetricResult<Long>> vWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            IprepdIO.METRICS_NAMESPACE, IprepdIO.VIOLATION_WRITES_METRIC))
                    .build())
            .getCounters();
    int cnt = 0;
    for (MetricResult<Long> x : vWrites) {
      assertEquals(35L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);
  }
}
