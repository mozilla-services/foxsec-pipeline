package com.mozilla.secops.authprofile;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.parser.ParserTest;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestAwsAssumeRoleCorrelator {

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private AuthProfile.AuthProfileOptions getTestOptions() {
    AuthProfile.AuthProfileOptions ret =
        PipelineOptionsFactory.as(AuthProfile.AuthProfileOptions.class);
    ret.setIdentityManagerPath("/testdata/identitymanager.json");
    ret.setEnableStateAnalysis(false);
    ret.setEnableCritObjectAnalysis(true);
    ret.setEnableAwsAssumeRoleCorrelator(true);
    ret.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    ret.setCritObjects(new String[] {"^projects/test$", "super-important-account"});
    ret.setCriticalNotificationEmail("section31@mozilla.com");
    ret.setIgnoreUserRegex(new String[] {"^riker@mozilla.com$"});
    ret.setContactEmail("test@localhost");
    ret.setDocLink("https://localhost");
    ret.setGenerateConfigurationTicksInterval(1);
    ret.setGenerateConfigurationTicksMaximum(5L);
    ret.setUseEventTimestampForAlert(true);
    return ret;
  }

  /**
   * Test cases:
   *
   * <p>2. "right" case: two events, but origin is an ec2 instance or something.
   *
   * <p>4. 1 event, trusted, trusting is missing. -> no alert, no errors 5. 1 event, trusting,
   * trusted is missing. -> no alert, no errors
   */
  @Test
  public void critObjectAwsAssumeRoleCrossAccountTest() throws Exception {
    // This testcase tests when a user assumes a role in a critical resource
    // We should be able to correlate the events between accounts and
    // generate an alert with the correct user information
    AuthProfile.AuthProfileOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_awscorr1a.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/authprof_awscorr1b.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkToInfinity();

    Input input = TestAuthProfileUtil.wiredInputStream(options, s);
    PCollection<Alert> res = AuthProfile.processInput(p.apply(input.simplexReadRaw()), options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long cnt = 0;
              long cfgTickCnt = 0;
              for (Alert a : results) {
                if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("critical_object_analyze")) {
                  assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                  assertEquals(
                      "critical authentication event observed "
                          + "uhura to super-important-account, 127.0.0.1 [unknown/unknown]",
                      a.getSummary());
                  assertThat(
                      a.getPayload(),
                      containsString(
                          "This destination object is configured as a critical resource"));
                  assertEquals(
                      "critical_object_analyze",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals(
                      "section31@mozilla.com",
                      a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  assertEquals("uhura", a.getMetadataValue(AlertMeta.Key.USERNAME));
                  assertEquals("super-important-account", a.getMetadataValue(AlertMeta.Key.OBJECT));
                  assertEquals("127.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("unknown", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY));
                  assertEquals("unknown", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertEquals("auth", a.getMetadataValue(AlertMeta.Key.AUTH_ALERT_TYPE));
                  cnt++;
                } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("cfgtick")) {
                  cfgTickCnt++;
                  assertEquals("authprofile-cfgtick", a.getCategory());
                  assertEquals(
                      "^projects/test$, super-important-account",
                      a.getCustomMetadataValue("critObjects"));
                  assertEquals(
                      "section31@mozilla.com",
                      a.getCustomMetadataValue("criticalNotificationEmail"));
                  assertEquals("^riker@mozilla.com$", a.getCustomMetadataValue("ignoreUserRegex"));
                  assertEquals("5", a.getCustomMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alert via section31@mozilla.com immediately on auth events to specified objects: [^projects/test$, super-important-account]",
                      a.getCustomMetadataValue("heuristic_CritObjectAnalyze"));
                } else {
                  fail("unexpected category");
                }
              }
              assertEquals(5L, cfgTickCnt);
              assertEquals(1L, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectAwsAssumeRoleSameAccountTest() throws Exception {
    // This testcase tests when a user assumes a role in a critical resource
    // from that account. There's no shared request ID and we should receive
    // a single alert for it from the regular crit object analyze.
    AuthProfile.AuthProfileOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_awscorr2.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Input input = TestAuthProfileUtil.wiredInputStream(options, s);
    PCollection<Alert> res = AuthProfile.processInput(p.apply(input.simplexReadRaw()), options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long cnt = 0;
              long cfgTickCnt = 0;
              for (Alert a : results) {
                if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("critical_object_analyze")) {
                  assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                  assertEquals(
                      "critical authentication event observed "
                          + "uhura to super-important-account, 127.0.0.1 [unknown/unknown]",
                      a.getSummary());
                  assertThat(
                      a.getPayload(),
                      containsString(
                          "This destination object is configured as a critical resource"));
                  assertEquals(
                      "critical_object_analyze",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals(
                      "section31@mozilla.com",
                      a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  assertEquals("uhura", a.getMetadataValue(AlertMeta.Key.USERNAME));
                  assertEquals("super-important-account", a.getMetadataValue(AlertMeta.Key.OBJECT));
                  assertEquals("127.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("unknown", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY));
                  assertEquals("unknown", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertEquals("auth", a.getMetadataValue(AlertMeta.Key.AUTH_ALERT_TYPE));
                  cnt++;
                } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("cfgtick")) {
                  cfgTickCnt++;
                  assertEquals("authprofile-cfgtick", a.getCategory());
                  assertEquals(
                      "^projects/test$, super-important-account",
                      a.getCustomMetadataValue("critObjects"));
                  assertEquals(
                      "section31@mozilla.com",
                      a.getCustomMetadataValue("criticalNotificationEmail"));
                  assertEquals("^riker@mozilla.com$", a.getCustomMetadataValue("ignoreUserRegex"));
                  assertEquals("5", a.getCustomMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alert via section31@mozilla.com immediately on auth events to specified objects: [^projects/test$, super-important-account]",
                      a.getCustomMetadataValue("heuristic_CritObjectAnalyze"));
                } else {
                  fail("unexpected category");
                }
              }
              assertEquals(5L, cfgTickCnt);
              assertEquals(1L, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectAwsAssumeRoleCrossAccountAwsService() throws Exception {
    // Contains a test for assumeRole called by a service. There's a shared
    // event id but because we shouldn't alert on it or try to correlate it.
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setGenerateConfigurationTicksInterval(0);

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_awscorr3.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Input input = TestAuthProfileUtil.wiredInputStream(options, s);
    PCollection<Alert> res = AuthProfile.processInput(p.apply(input.simplexReadRaw()), options);

    PAssert.that(res).empty();
    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectAwsAssumeRoleCrossAccountTrustingOnlyTest() throws Exception {
    // This testcase tests when a user assumes a role in a critical resource
    // from another account, but we are missing the trusted accounts cloudtrail logs.
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setGenerateConfigurationTicksInterval(0);

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_awscorr1a.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Input input = TestAuthProfileUtil.wiredInputStream(options, s);
    PCollection<Alert> res = AuthProfile.processInput(p.apply(input.simplexReadRaw()), options);

    PAssert.that(res).empty();
    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectAwsAssumeRoleCrossAccountTrustedOnlyTest() throws Exception {
    // This testcase tests when a user assumes a role in a critical resource
    // from another account, but we are missing the event for the trusted account
    // which is the critical resource.
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setGenerateConfigurationTicksInterval(0);

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_awscorr1b.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Input input = TestAuthProfileUtil.wiredInputStream(options, s);
    PCollection<Alert> res = AuthProfile.processInput(p.apply(input.simplexReadRaw()), options);

    PAssert.that(res).empty();
    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectAwsAssumeRoleCrossAccountDelayBetweenEventsTest() throws Exception {
    // This testcase tests when a user assumes a role in a critical resource
    // We should be able to correlate the events between accounts and
    // generate an alert with the correct user information
    AuthProfile.AuthProfileOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_awscorr1a.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/authprof_awscorr1c.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(Instant.parse("2020-10-20T15:21:00Z"))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(Instant.parse("2020-10-20T15:22:00Z"))
            .advanceProcessingTime(Duration.standardSeconds(70))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkToInfinity();

    Input input = TestAuthProfileUtil.wiredInputStream(options, s);
    PCollection<Alert> res = AuthProfile.processInput(p.apply(input.simplexReadRaw()), options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long cnt = 0;
              long cfgTickCnt = 0;
              for (Alert a : results) {
                if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("critical_object_analyze")) {
                  assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                  assertEquals(
                      "critical authentication event observed "
                          + "uhura to super-important-account, 127.0.0.1 [unknown/unknown]",
                      a.getSummary());
                  assertThat(
                      a.getPayload(),
                      containsString(
                          "This destination object is configured as a critical resource"));
                  assertEquals(
                      "critical_object_analyze",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals(
                      "section31@mozilla.com",
                      a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  assertEquals("uhura", a.getMetadataValue(AlertMeta.Key.USERNAME));
                  assertEquals("super-important-account", a.getMetadataValue(AlertMeta.Key.OBJECT));
                  assertEquals("127.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("unknown", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY));
                  assertEquals("unknown", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertEquals("auth", a.getMetadataValue(AlertMeta.Key.AUTH_ALERT_TYPE));
                  cnt++;
                } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("cfgtick")) {
                  cfgTickCnt++;
                  assertEquals("authprofile-cfgtick", a.getCategory());
                  assertEquals(
                      "^projects/test$, super-important-account",
                      a.getCustomMetadataValue("critObjects"));
                  assertEquals(
                      "section31@mozilla.com",
                      a.getCustomMetadataValue("criticalNotificationEmail"));
                  assertEquals("^riker@mozilla.com$", a.getCustomMetadataValue("ignoreUserRegex"));
                  assertEquals("5", a.getCustomMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alert via section31@mozilla.com immediately on auth events to specified objects: [^projects/test$, super-important-account]",
                      a.getCustomMetadataValue("heuristic_CritObjectAnalyze"));
                } else {
                  fail("unexpected category");
                }
              }
              assertEquals(5L, cfgTickCnt);
              assertEquals(1L, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
