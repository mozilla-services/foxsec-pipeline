package com.mozilla.secops.authprofile;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertConfiguration;
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
    ret.setCritObjects(new String[] {"^projects/test$"});
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
                if (a.getMetadataValue("category").equals("critical_object_analyze")) {
                  assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                  assertEquals(
                      "critical authentication event observed laforge@mozilla.com to "
                          + "projects/test, 216.160.83.56 [Milton/US]",
                      a.getSummary());
                  assertThat(
                      a.getPayload(),
                      containsString(
                          "This destination object is configured as a critical resource"));
                  assertEquals("critical_object_analyze", a.getMetadataValue("category"));
                  assertEquals("section31@mozilla.com", a.getMetadataValue("notify_email_direct"));
                  assertEquals("laforge@mozilla.com", a.getMetadataValue("username"));
                  assertEquals("projects/test", a.getMetadataValue("object"));
                  assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                  assertEquals("Milton", a.getMetadataValue("sourceaddress_city"));
                  assertEquals("US", a.getMetadataValue("sourceaddress_country"));
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertEquals("auth_session", a.getMetadataValue("auth_alert_type"));

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
                } else if (a.getMetadataValue("category").equals("cfgtick")) {
                  cfgTickCnt++;
                  assertEquals("authprofile-cfgtick", a.getCategory());
                  assertEquals("^projects/test$", a.getMetadataValue("critObjects"));
                  assertEquals(
                      "section31@mozilla.com", a.getMetadataValue("criticalNotificationEmail"));
                  assertEquals("^riker@mozilla.com$", a.getMetadataValue("ignoreUserRegex"));
                  assertEquals("5", a.getMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alert via section31@mozilla.com immediately on auth events to specified objects: [^projects/test$]",
                      a.getMetadataValue("heuristic_CritObjectAnalyze"));
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
