package com.mozilla.secops.amo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.TestIprepdIO;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertConfiguration;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.TemplateManager;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.input.InputElement;
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
import org.apache.beam.sdk.transforms.MapElements;
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
    ret.setInputIprepd("http://127.0.0.1:8080|test");
    ret.setOutputIprepd(new String[] {"http://127.0.0.1:8080|test"});
    ret.setAccountMatchBanOnLogin(new String[] {"locutus.*"});
    ret.setAddonMatchCriteria(new String[] {".*test_submission.*:7500:7500"});
    // Reduce the required country match count for the IP login tests here
    ret.setAddonMultiIpLoginAlertOn(2);
    ret.setAddonMultiIpLoginAlertOnIp(2);
    // Generate cfgticks
    ret.setGenerateConfigurationTicksInterval(1);
    ret.setGenerateConfigurationTicksMaximum(5L);
    return ret;
  }

  public TestAmo() {}

  @Test
  public void amoFxaAbuseNewVersionTest() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/amo_fxaacctabuse_newversion/block1.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/amo_fxaacctabuse_newversion/block2.txt");
    String[] eb3 = TestUtil.getTestInputArray("/testdata/amo_fxaacctabuse_newversion/block3.txt");

    Amo.AmoOptions options = getTestOptions();

    // Simulate recorded bad reputation for two email addresses and an IP
    TestIprepdIO.putReputation("email", "kurn@mozilla.com", 0);
    TestIprepdIO.putReputation("email", "locutus@mozilla.com", 0);
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

    InputElement e =
        new InputElement(options.getMonitoredResourceIndicator())
            .addWiredStream(s)
            .setConfigurationTicks(
                Amo.buildConfigurationTick(options),
                options.getGenerateConfigurationTicksInterval(),
                options.getGenerateConfigurationTicksMaximum());

    PCollection<String> input =
        p.apply(
            "input",
            new Input(options.getProject()).simplex().withInputElement(e).simplexReadRaw());

    PCollection<Alert> alerts =
        Amo.executePipeline(p, input, options)
            .apply(ParDo.of(new AlertFormatter(getTestOptions())));

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    alerts
        .apply(MapElements.via(new AlertFormatter.AlertToString()))
        .apply(OutputOptions.compositeOutput(getTestOptions()));

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(16L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int cntNewVersionLogin = 0;
              int cntRestriction = 0;
              int cntNewVersionBanPattern = 0;
              int cntAbuseAlias = 0;
              int cntMatchedAddon = 0;
              int cntMultiMatch = 0;
              int cntMultiSubmit = 0;
              int cntCloudSubmit = 0;
              int cntIpLogin = 0;
              int cntNewVersionSubmission = 0;
              for (Alert a : x) {
                if (a.getCategory().equals("amo")) {
                  if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("fxa_account_abuse_new_version_login")) {
                    if (a.getMetadataValue(AlertMeta.Key.EMAIL).equals("kurn@mozilla.com")) {
                      assertEquals("fxa_account_abuse_new_version_login", a.getNotifyMergeKey());
                      assertEquals("kurn@mozilla.com", a.getMetadataValue(AlertMeta.Key.EMAIL));
                      assertEquals(
                          "255.255.25.26", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                      assertEquals(
                          "test login to amo from suspected fraudulent account, kurn@mozilla.com "
                              + "from 255.255.25.26",
                          a.getSummary());
                    } else if (a.getMetadataValue(AlertMeta.Key.EMAIL)
                        .equals("locutus@mozilla.com")) {
                      assertEquals("fxa_account_abuse_new_version_login", a.getNotifyMergeKey());
                      assertEquals("locutus@mozilla.com", a.getMetadataValue(AlertMeta.Key.EMAIL));
                      assertEquals(
                          "255.255.25.30", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                      assertEquals(
                          "test login to amo from suspected fraudulent account, locutus@mozilla.com "
                              + "from 255.255.25.30",
                          a.getSummary());
                    } else {
                      fail("unexpected email address");
                    }
                    cntNewVersionLogin++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("amo_restriction")) {
                    assertEquals("amo_restriction", a.getNotifyMergeKey());
                    assertEquals(
                        "kurn@mozilla.com", a.getMetadataValue(AlertMeta.Key.RESTRICTED_VALUE));
                    assertEquals(
                        "test request to amo from kurn@mozilla.com restricted based on reputation",
                        a.getSummary());
                    cntRestriction++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("fxa_account_abuse_new_version_login_banpattern")) {
                    assertEquals(
                        "fxa_account_abuse_new_version_login_banpattern", a.getNotifyMergeKey());
                    assertEquals("locutus@mozilla.com", a.getMetadataValue(AlertMeta.Key.EMAIL));
                    assertEquals("255.255.25.30", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    cntNewVersionBanPattern++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("fxa_account_abuse_alias")) {
                    assertEquals("fxa_account_abuse_alias", a.getNotifyMergeKey());
                    assertEquals("6", a.getMetadataValue(AlertMeta.Key.COUNT));
                    assertEquals(
                        "test possible alias abuse in amo, laforge@mozilla.com has 6 aliases",
                        a.getSummary());
                    cntAbuseAlias++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("amo_abuse_matched_addon")) {
                    assertEquals("amo_abuse_matched_addon", a.getNotifyMergeKey());
                    assertEquals("216.160.83.63", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    assertEquals(
                        "00000000000000000000000000000000_test_submission.zip",
                        a.getMetadataValue(AlertMeta.Key.ADDON_FILENAME));
                    assertEquals("lwaxana@mozilla.com", a.getMetadataValue(AlertMeta.Key.EMAIL));
                    assertEquals("7500", a.getMetadataValue(AlertMeta.Key.ADDON_SIZE));
                    assertEquals(
                        "test suspected malicious addon submission from 216.160.83.63, lwaxana@mozilla.com",
                        a.getSummary());
                    cntMatchedAddon++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("amo_abuse_multi_match")) {
                    cntMultiMatch++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("amo_abuse_multi_submit")) {
                    assertEquals("amo_abuse_multi_submit", a.getNotifyMergeKey());
                    assertEquals("test addon abuse multi submit, 10000 11", a.getSummary());
                    assertEquals("11", a.getMetadataValue(AlertMeta.Key.COUNT));
                    cntMultiSubmit++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("amo_abuse_multi_ip_login")) {
                    assertEquals("amo_abuse_multi_ip_login", a.getNotifyMergeKey());
                    assertEquals(
                        "test addon abuse multi ip country login, sevenofnine@mozilla.net 2 countr"
                            + "ies, 2 source address",
                        a.getSummary());
                    assertEquals("2", a.getMetadataValue(AlertMeta.Key.COUNT));
                    cntIpLogin++;
                  } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                      .equals("amo_cloud_submission")) {
                    assertEquals("aws", a.getMetadataValue(AlertMeta.Key.PROVIDER));
                    assertEquals("52.204.100.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    assertEquals("tashayar@mozilla.com", a.getMetadataValue(AlertMeta.Key.EMAIL));
                    assertEquals("extension_guid", a.getMetadataValue(AlertMeta.Key.ADDON_GUID));
                    assertEquals("99999999", a.getMetadataValue(AlertMeta.Key.ADDON_USER_ID));
                    assertEquals("true", a.getMetadataValue(AlertMeta.Key.ADDON_FROM_API));
                    assertEquals(
                        "test cloud provider addon submission from 52.204.100.1, guid extension_guid"
                            + " isapi true user_id 99999999",
                        a.getSummary());
                    assertEquals("slack/catchall/amo.ftlh", a.getSlackCatchallTemplate());

                    // Test slack template rendereing
                    try {
                      AlertConfiguration alertCfg = new AlertConfiguration();
                      alertCfg.registerTemplate(a.getSlackCatchallTemplate());
                      TemplateManager tmgr = new TemplateManager(alertCfg);
                      tmgr.validate();
                      String catchallText =
                          tmgr.processTemplate(
                              a.getSlackCatchallTemplate(), a.generateTemplateVariables());
                      assertEquals(
                          String.format(
                              "test cloud provider addon submission from 52.204.100.1, guid"
                                  + " <https://addons-internal.prod.mozaws.net/en-US/admin/models/addons/addon/extension_guid/change/|extension_guid>"
                                  + " isapi true user_id"
                                  + " <https://addons-internal.prod.mozaws.net/en-US/admin/models/users/userprofile/99999999/change/|99999999>"
                                  + " (%s)\n",
                              a.getAlertId()),
                          catchallText);
                    } catch (Exception exc) {
                      fail(exc.getMessage());
                    }

                    cntCloudSubmit++;
                  } else {
                    assertEquals("255.255.25.25", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    if (a.getMetadataValue(AlertMeta.Key.ADDON_VERSION) != null) {
                      assertEquals(
                          "fxa_account_abuse_new_version_submission", a.getNotifyMergeKey());
                      assertEquals("1.0.0", a.getMetadataValue(AlertMeta.Key.ADDON_VERSION));
                      assertEquals("0000001", a.getMetadataValue(AlertMeta.Key.ADDON_ID));
                      assertEquals(
                          "test addon submission from address associated with "
                              + "suspected fraudulent account, 255.255.25.25",
                          a.getSummary());
                    } else {
                      assertEquals(
                          "fxa_account_abuse_new_version_submission", a.getNotifyMergeKey());
                      assertNull(a.getMetadataValue(AlertMeta.Key.ADDON_VERSION));
                      assertNull(a.getMetadataValue(AlertMeta.Key.ADDON_ID));
                      assertEquals(
                          "test addon submission from address associated with "
                              + "suspected fraudulent account, 255.255.25.25",
                          a.getSummary());
                    }
                    cntNewVersionSubmission++;
                  }
                } else if (a.getCategory().equals("amo-cfgtick")) {
                  assertEquals(
                      "Correlates AMO addon submissions with abusive FxA account creation alerts via iprepd. Also includes blocked accounts regex: [locutus.*]",
                      a.getCustomMetadataValue("heuristic_FxaAccountAbuseNewVersion"));
                  assertEquals(
                      "Reports on request restrictions from AMO",
                      a.getCustomMetadataValue("heuristic_ReportRestriction"));
                  assertEquals(
                      "Alerts on aliased FxA accounts usage. A max of 5 are allowed for one account in a given session.",
                      a.getCustomMetadataValue("heuristic_FxaAccountAbuseAlias"));
                  assertEquals(
                      "Match abusive addon uploads using these patterns [.*test_submission.*:7500:7500] and generate alerts",
                      a.getCustomMetadataValue("heuristic_AddonMatcher"));
                  assertEquals(
                      "Detect distributed AMO submissions with the same file hash. Alert on 5 submissions of the same file name.",
                      a.getCustomMetadataValue("heuristic_AddonMultiMatch"));
                  assertEquals(
                      "Detect distributed submissions based on file size intervals. Alert on 10 submissions of the same rounded interval.",
                      a.getCustomMetadataValue("heuristic_AddonMultiSubmit"));
                  assertEquals(
                      "Detect multiple account logins for the same account from different source addresses associated with different country codes. Alert on 2 different countries and 2 different IPs. Regex for account exceptions: null",
                      a.getCustomMetadataValue("heuristic_AddonMultiIpLogin"));
                } else {
                  fail("unexpected category");
                }
              }
              assertEquals("cntNewVersionLogin", 2, cntNewVersionLogin);
              assertEquals("cntRestriction", 1, cntRestriction);
              assertEquals("cntNewVersionBanPattern", 1, cntNewVersionBanPattern);
              assertEquals("cntAbuseAlias", 1, cntAbuseAlias);
              assertEquals("cntMatchedAddon", 1, cntMatchedAddon);
              assertEquals("cntMultiMatch", 0, cntMultiMatch);
              assertEquals("cntMultiSubmit", 1, cntMultiSubmit);
              assertEquals("cntIpLogin", 1, cntIpLogin);
              assertEquals("cntNewVersionSubmission", 2, cntNewVersionSubmission);
              assertEquals("cntCloudSubmit", 1, cntCloudSubmit);
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
      assertEquals(26L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> cloudSubMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            AddonCloudSubmission.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : cloudSubMWrites) {
      assertEquals(3L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> addonMatcherMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            AddonMatcher.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : addonMatcherMWrites) {
      assertEquals(19L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> addonMultiIpLoginMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            AddonMultiIpLogin.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : addonMultiIpLoginMWrites) {
      assertEquals(22L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> addonMultiMatchMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            AddonMultiMatch.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : addonMultiMatchMWrites) {
      assertEquals(19L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> addonMultiSubmitMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            AddonMultiSubmit.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : addonMultiSubmitMWrites) {
      assertEquals(19L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> fxaAccountAbuseAliasMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            FxaAccountAbuseAlias.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : fxaAccountAbuseAliasMWrites) {
      assertEquals(9L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> fxaAccountAbuseNewVersionMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            FxaAccountAbuseNewVersion.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : fxaAccountAbuseNewVersionMWrites) {
      assertEquals(23L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);

    Iterable<MetricResult<Long>> reportRestrictionMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            ReportRestriction.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : reportRestrictionMWrites) {
      assertEquals(1L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);
  }

  @Test
  public void testMultiMatch() throws Exception {
    Amo.AmoOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/amo_multimatch/block1.txt");

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    InputElement e = new InputElement(options.getMonitoredResourceIndicator()).addWiredStream(s);

    PCollection<String> input =
        p.apply(
            "input",
            new Input(options.getProject()).simplex().withInputElement(e).simplexReadRaw());

    PCollection<Alert> alerts =
        Amo.executePipeline(p, input, options)
            .apply(ParDo.of(new AlertFormatter(getTestOptions())));

    PCollection<Long> count = alerts.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(1L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertEquals("amo_abuse_multi_match", a.getNotifyMergeKey());
                assertEquals("test addon abuse multi match, 10", a.getSummary());
                assertEquals("10", a.getMetadataValue(AlertMeta.Key.COUNT));
                assertEquals(
                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    a.getMetadataValue(AlertMeta.Key.ADDON_UPLOAD_HASH));
              }
              return null;
            });

    PipelineResult pResult = p.run();
    pResult.waitUntilFinish();
  }

  @Test
  public void testFxaAliasAbuseDotNormalization() throws Exception {
    Amo.AmoOptions options = getTestOptions();

    String[] eb1 =
        TestUtil.getTestInputArray("/testdata/amo_fxaaliasabuse/dotnormalizationabuse.txt");

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    InputElement e = new InputElement(options.getMonitoredResourceIndicator()).addWiredStream(s);

    PCollection<String> input =
        p.apply(
            "input",
            new Input(options.getProject()).simplex().withInputElement(e).simplexReadRaw());

    PCollection<Alert> alerts =
        Amo.executePipeline(p, input, options)
            .apply(ParDo.of(new AlertFormatter(getTestOptions())));

    PCollection<Long> count = alerts.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(1L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              for (Alert a : x) {
                assertEquals("fxa_account_abuse_alias", a.getNotifyMergeKey());
                assertEquals("6", a.getMetadataValue(AlertMeta.Key.COUNT));
                assertEquals(
                    "test possible alias abuse in amo, test12345@example-email.com has 6 aliases",
                    a.getSummary());
              }
              return null;
            });

    PipelineResult pResult = p.run();
    pResult.waitUntilFinish();

    int cnt;

    Iterable<MetricResult<Long>> fxaAccountAbuseAliasMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            FxaAccountAbuseAlias.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : fxaAccountAbuseAliasMWrites) {
      assertEquals(7L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);
  }

  @Test
  public void testFxaAliasAbuseDotNormalizationNonDistinct() throws Exception {
    Amo.AmoOptions options = getTestOptions();

    String[] eb1 =
        TestUtil.getTestInputArray("/testdata/amo_fxaaliasabuse/dotnormalizationabuse2.txt");

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    InputElement e = new InputElement(options.getMonitoredResourceIndicator()).addWiredStream(s);

    PCollection<String> input =
        p.apply(
            "input",
            new Input(options.getProject()).simplex().withInputElement(e).simplexReadRaw());

    PCollection<Alert> alerts =
        Amo.executePipeline(p, input, options)
            .apply(ParDo.of(new AlertFormatter(getTestOptions())));

    PCollection<Long> count = alerts.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(0L);

    PipelineResult pResult = p.run();
    pResult.waitUntilFinish();

    int cnt;

    Iterable<MetricResult<Long>> fxaAccountAbuseAliasMWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            FxaAccountAbuseAlias.class.getName(),
                            AmoMetrics.HeuristicMetrics.EVENT_TYPE_MATCH))
                    .build())
            .getCounters();
    cnt = 0;
    for (MetricResult<Long> x : fxaAccountAbuseAliasMWrites) {
      assertEquals(7L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);
  }
}
