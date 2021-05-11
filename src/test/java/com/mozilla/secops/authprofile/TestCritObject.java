package com.mozilla.secops.authprofile;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertConfiguration;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.TemplateManager;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.parser.ParserTest;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestCritObject {
  public TestCritObject() {}

  private AuthProfile.AuthProfileOptions getTestOptions() {
    AuthProfile.AuthProfileOptions ret =
        PipelineOptionsFactory.as(AuthProfile.AuthProfileOptions.class);
    ret.setIdentityManagerPath("/testdata/identitymanager.json");
    ret.setEnableStateAnalysis(false);
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

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void critObjectTest() throws Exception {
    AuthProfile.AuthProfileOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_critobj1.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/authprof_critobj2.txt");
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
                      "critical authentication event observed laforge@mozilla.com to "
                          + "projects/test, 216.160.83.56 [Milton/US]",
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
                  assertEquals("laforge@mozilla.com", a.getMetadataValue(AlertMeta.Key.USERNAME));
                  assertEquals("projects/test", a.getMetadataValue(AlertMeta.Key.OBJECT));
                  assertEquals("216.160.83.56", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("Milton", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY));
                  assertEquals("US", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertEquals("auth_session", a.getMetadataValue(AlertMeta.Key.AUTH_ALERT_TYPE));

                  // Verify sample rendered email template for critical object
                  try {
                    TemplateManager tmgr = new TemplateManager(new AlertConfiguration());
                    String templateOutput =
                        tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
                    assertEquals(
                        TestAuthProfile.renderTestTemplate(
                            "/testdata/templateoutput/email/authprof_critobj.html", a),
                        templateOutput);
                  } catch (Exception exc) {
                    fail(exc.getMessage());
                  }
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
              // We should have 2; 3 alerts would have been generated in total with the second one
              // being suppressed
              assertEquals(2L, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectAwsSwitchRoleTest() throws Exception {
    AuthProfile.AuthProfileOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_critobj4.txt");
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
  public void critObjectTestSupplementaryPolicy() throws Exception {
    AuthProfile.AuthProfileOptions options = getTestOptions();

    options.setGenerateConfigurationTicksInterval(0);
    options.setAlternateCritSlackEscalation("EST:8:10:test");

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_critobj3.txt");
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
              int cnt = 0;
              int ncnt = 0;
              int scnt = 0;
              for (Alert a : results) {
                long m = a.getTimestamp().getMillis();
                if (m == 1546349400000L) {
                  // Will be our alternate escalation
                  assertNull(a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  assertThat(
                      a.getMetadataValue(AlertMeta.Key.SLACK_SUPPLEMENTARY_MESSAGE),
                      containsString(
                          "<!channel> critical authentication event observed laforge@mozilla.com to "
                              + "projects/test, 216.160.83.56 [Milton/US]\n"
                              + "alert id:"));
                  assertEquals(
                      "test", a.getMetadataValue(AlertMeta.Key.NOTIFY_SLACK_SUPPLEMENTARY));
                  scnt++;
                } else if (m == 1546383600000L || m == 1546695000000L) {
                  // Will be a standard escalation
                  assertEquals(
                      "section31@mozilla.com",
                      a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  assertThat(
                      a.getMetadataValue(AlertMeta.Key.SLACK_SUPPLEMENTARY_MESSAGE),
                      containsString(
                          "critical authentication event observed laforge@mozilla.com to "
                              + "projects/test, 216.160.83.56 [Milton/US]\n"
                              + "Notification has been sent to section31@mozilla.com\n"
                              + "alert id: "));
                  assertEquals(
                      "test", a.getMetadataValue(AlertMeta.Key.NOTIFY_SLACK_SUPPLEMENTARY));
                  ncnt++;
                } else {
                  fail("unexpected alert timestamp");
                }
                cnt++;
              }
              assertEquals(2, ncnt);
              assertEquals(1, scnt);
              assertEquals(3, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectTestSupplementaryPolicyMissingPolicy() throws Exception {
    AuthProfile.AuthProfileOptions options = getTestOptions();

    options.setGenerateConfigurationTicksInterval(0);
    options.setAlternateCritSlackEscalation("EST:8:10:test");
    options.setCriticalNotificationEmail(null);

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_critobj3.txt");
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
              int cnt = 0;
              int ncnt = 0;
              int scnt = 0;
              for (Alert a : results) {
                long m = a.getTimestamp().getMillis();
                if (m == 1546349400000L) {
                  // Will be our alternate escalation
                  assertNull(a.getMetadataValue(AlertMeta.Key.NOTIFY_EMAIL_DIRECT));
                  assertThat(
                      a.getMetadataValue(AlertMeta.Key.SLACK_SUPPLEMENTARY_MESSAGE),
                      containsString(
                          "<!channel> critical authentication event observed laforge@mozilla.com to "
                              + "projects/test, 216.160.83.56 [Milton/US]\n"
                              + "alert id:"));
                  assertEquals(
                      "test", a.getMetadataValue(AlertMeta.Key.NOTIFY_SLACK_SUPPLEMENTARY));
                  scnt++;
                } else if (m == 1546383600000L || m == 1546695000000L) {
                  // No standard escalation cos email not set
                  assertThat(
                      a.getMetadataValue(AlertMeta.Key.SLACK_SUPPLEMENTARY_MESSAGE),
                      containsString(
                          "critical authentication event observed laforge@mozilla.com to "
                              + "projects/test, 216.160.83.56 [Milton/US]\n"
                              + "Notification has been sent to no one! <!channel>\n"
                              + "alert id: "));
                  assertEquals(
                      "test", a.getMetadataValue(AlertMeta.Key.NOTIFY_SLACK_SUPPLEMENTARY));
                  ncnt++;
                } else {
                  fail("unexpected alert timestamp");
                }
                cnt++;
              }
              assertEquals(2, ncnt);
              assertEquals(1, scnt);
              assertEquals(3, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void critObjectWithSessionBasedSuppressionTest() throws Exception {
    AuthProfile.AuthProfileOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/authprof_critobj8.txt");
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
                      "critical authentication event observed laforge@mozilla.com to "
                          + "projects/test, 216.160.83.56 [Milton/US]",
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
                  assertEquals("laforge@mozilla.com", a.getMetadataValue(AlertMeta.Key.USERNAME));
                  assertEquals("projects/test", a.getMetadataValue(AlertMeta.Key.OBJECT));
                  assertEquals("216.160.83.56", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("Milton", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY));
                  assertEquals("US", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertEquals("auth_session", a.getMetadataValue(AlertMeta.Key.AUTH_ALERT_TYPE));

                  // Verify sample rendered email template for critical object
                  try {
                    TemplateManager tmgr = new TemplateManager(new AlertConfiguration());
                    String templateOutput =
                        tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
                    assertEquals(
                        TestAuthProfile.renderTestTemplate(
                            "/testdata/templateoutput/email/authprof_critobj.html", a),
                        templateOutput);
                  } catch (Exception exc) {
                    fail(exc.getMessage());
                  }
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
              // We should have 2; 3 alerts would have been generated in total with the second one
              // being suppressed
              assertEquals(2L, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
