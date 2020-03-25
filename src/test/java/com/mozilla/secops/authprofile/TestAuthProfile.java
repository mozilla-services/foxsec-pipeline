package com.mozilla.secops.authprofile;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.mozilla.secops.Minfraud;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertConfiguration;
import com.mozilla.secops.alert.AlertIO;
import com.mozilla.secops.alert.TemplateManager;
import com.mozilla.secops.authstate.AuthStateModel;
import com.mozilla.secops.authstate.PruningStrategyEntryAge;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.ParserTest;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.util.Collection;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class TestAuthProfile {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  public static String renderTestTemplate(String path, Alert a) {
    String in;
    try {
      in = TestUtil.getTestResource(path);
    } catch (IOException exc) {
      return null;
    }
    if (in == null) {
      return null;
    }

    in = in.replaceAll("DATESTAMP", a.getMetadataValue("event_timestamp"));

    if (a.getMetadataValue("event_timestamp_source_local") != null) {
      in = in.replaceAll("DATELOCALSTAMP", a.getMetadataValue("event_timestamp_source_local"));
    }

    return in.replaceAll("ALERTID", a.getAlertId().toString());
  }

  private void testEnv() throws Exception {
    environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
    environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
    environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
    environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
    clearState();
  }

  public TestAuthProfile() {}

  public void clearState() throws Exception {
    State state = new State(new DatastoreStateInterface("authprofile", "testauthprofileanalyze"));
    state.initialize();
    state.deleteAll();
    state.done();
    Minfraud.cacheClear();
    Minfraud.setCacheOnly(true);
  }

  private AuthProfile.AuthProfileOptions getTestOptions() {
    AuthProfile.AuthProfileOptions ret =
        PipelineOptionsFactory.as(AuthProfile.AuthProfileOptions.class);
    ret.setDatastoreNamespace("testauthprofileanalyze");
    ret.setDatastoreKind("authprofile");
    ret.setIdentityManagerPath("/testdata/identitymanager.json");
    ret.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    ret.setContactEmail("test@localhost");
    ret.setDocLink("https://localhost");
    return ret;
  }

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void parseExtractGBKTest() throws Exception {
    testEnv();
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer1.txt", p);

    PCollection<KV<String, Iterable<Event>>> res =
        input
            .apply(new AuthProfile.Parse(getTestOptions()))
            .apply(ParDo.of(new AuthProfile.ExtractIdentity(getTestOptions())))
            .apply(new GlobalTriggers<KV<String, Event>>(60))
            .apply(GroupByKey.<String, Event>create());
    PAssert.thatMap(res)
        .satisfies(
            results -> {
              Iterable<Event> edata = results.get("wriker@mozilla.com");
              assertNotNull(edata);
              assertTrue(edata instanceof Collection);

              Event[] e = ((Collection<Event>) edata).toArray(new Event[0]);
              assertEquals(5, e.length);

              Normalized n = e[0].getNormalized();
              assertNotNull(n);
              assertTrue(n.isOfType(Normalized.Type.AUTH));
              assertEquals("216.160.83.56", n.getSourceAddress());
              assertEquals("riker", n.getSubjectUser());

              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeTest() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();

    // Enable configuration tick generation in the pipeline for this test, and use Input
    //
    // Also, leave minFraud disabled here
    options.setInputFile(new String[] {"./target/test-classes/testdata/authprof_buffer1.txt"});
    options.setGenerateConfigurationTicksInterval(1);
    options.setGenerateConfigurationTicksMaximum(5L);
    options.setEnableCritObjectAnalysis(false);
    PCollection<String> input =
        p.apply(
            "input",
            Input.compositeInputAdapter(options, AuthProfile.buildConfigurationTick(options)));

    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              long cfgTickCnt = 0;
              for (Alert a : results) {
                if (a.getMetadataValue("category").equals("state_analyze")) {
                  assertEquals("authprofile", a.getCategory());
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                  String actualSummary = a.getSummary();
                  if (actualSummary.equals(
                      "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                          + "216.160.83.56 [Milton/US]")) {
                    assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                    assertEquals("Milton", a.getMetadataValue("sourceaddress_city"));
                    assertEquals("US", a.getMetadataValue("sourceaddress_country"));
                    infoCnt++;
                    assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                    assertNull(a.getMetadataValue("notify_email_direct"));
                    assertNull(a.getMetadataValue("escalate_to"));
                    assertEquals("known_ip", a.getMetadataValue("state_action_type"));

                    // Verify sample rendered email template for known source
                    try {
                      AlertConfiguration alertCfg = new AlertConfiguration();
                      alertCfg.registerTemplate("email/authprofile.ftlh");
                      TemplateManager tmgr = new TemplateManager(alertCfg);
                      tmgr.validate();
                      String templateOutput =
                          tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
                      assertEquals(
                          "known ip",
                          renderTestTemplate(
                              "/testdata/templateoutput/email/authprof_state_known.html", a),
                          templateOutput);
                    } catch (Exception exc) {
                      fail(exc.getMessage());
                    }
                  } else if (actualSummary.equals(
                      "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                          + "new source 216.160.83.56 [Milton/US]")) {
                    assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                    assertEquals("Milton", a.getMetadataValue("sourceaddress_city"));
                    assertEquals("US", a.getMetadataValue("sourceaddress_country"));
                    newCnt++;
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertNull(a.getMetadataValue("notify_email_direct"));
                    assertEquals(a.getMetadataValue("notify_slack_direct"), "wriker@mozilla.com");
                    assertEquals(
                        a.getMetadataValue("alert_notification_type"), "slack_confirmation");
                    assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
                    // Should be indicated as an unknown IP, and minFraud/GeoIP failure as we have
                    // not configured minFraud
                    assertEquals(
                        "unknown_ip_minfraud_geo_failure", a.getMetadataValue("state_action_type"));

                    // Verify sample rendered email template for new source
                    try {
                      TemplateManager tmgr = new TemplateManager(new AlertConfiguration());
                      tmgr.validate();
                      String templateOutput =
                          tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
                      assertEquals(
                          "new ip",
                          renderTestTemplate(
                              "/testdata/templateoutput/email/authprof_state_new.html", a),
                          templateOutput);
                    } catch (Exception exc) {
                      fail(exc.getMessage());
                    }
                  }
                  assertEquals("state_analyze", a.getMetadataValue("category"));
                  assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                  assertEquals("riker", a.getMetadataValue("username"));
                  assertEquals("emit-bastion", a.getMetadataValue("object"));
                  assertEquals("2018-09-18T22:15:38.000Z", a.getMetadataValue("event_timestamp"));
                  assertEquals(
                      "2018-09-18T15:15:38.000-07:00",
                      a.getMetadataValue("event_timestamp_source_local"));
                } else if (a.getMetadataValue("category").equals("cfgtick")) {
                  cfgTickCnt++;
                  assertEquals("authprofile-cfgtick", a.getCategory());
                  assertEquals("testauthprofileanalyze", a.getMetadataValue("datastoreNamespace"));
                  assertEquals(
                      "./target/test-classes/testdata/authprof_buffer1.txt",
                      a.getMetadataValue("inputFile"));
                  assertEquals("authprofile", a.getMetadataValue("datastoreKind"));
                  assertEquals("5", a.getMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alert if an identity (can be thought of as a user) authenticates from a new IP",
                      a.getMetadataValue("heuristic_StateAnalyze"));
                  assertNull(a.getMetadataValue("heuristic_CritObjectAnalyze"));
                } else {
                  fail("unexpected category");
                }
              }
              assertEquals(5L, cfgTickCnt);
              assertEquals(1L, newCnt);
              // Should have one informational since the rest of the duplicates will be
              // filtered in window since they were already seen
              assertEquals(1L, infoCnt);

              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeMixedTest() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    Minfraud.cacheInsightsResource("216.160.83.56", "/testdata/minfraud/insights_normal1.json");
    Minfraud.cacheInsightsResource("127.0.0.1", "/testdata/minfraud/insights_normal1.json");
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer2.txt", p);

    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                assertEquals("state_analyze", a.getMetadataValue("category"));
                String actualSummary = a.getSummary();
                if (actualSummary.contains("new source")) {
                  newCnt++;
                } else {
                  infoCnt++;
                }

                String iKey = a.getMetadataValue("identity_key");
                if (a.getMetadataValue("username").equals("laforge@mozilla.com")) {
                  // Identity lookup should have failed
                  assertNull(iKey);
                  assertNull(a.getMetadataValue("notify_email_direct"));

                  // Severity should be informational since it is an untracked identity
                  assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                  assertEquals("127.0.0.1", a.getMetadataValue("sourceaddress"));
                  assertEquals("laforge@mozilla.com", a.getMetadataValue("username"));
                  assertEquals("true", a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                  assertThat(a.getSummary(), containsString("untracked"));
                  assertEquals("2019-01-03T20:52:04.782Z", a.getMetadataValue("event_timestamp"));
                  // No action type on untracked identity
                  assertNull(a.getMetadataValue("state_action_type"));
                } else if ((iKey != null) && (iKey.equals("wriker@mozilla.com"))) {
                  if (a.getMetadataValue("username").equals("riker@mozilla.com")) {
                    // GcpAudit event should have generated a warning
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertNull(a.getMetadataValue("notify_email_direct"));
                    assertEquals(a.getMetadataValue("notify_slack_direct"), "wriker@mozilla.com");
                    assertEquals(
                        a.getMetadataValue("alert_notification_type"), "slack_confirmation");
                    assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                    assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                    assertEquals("2019-01-03T20:52:04.782Z", a.getMetadataValue("event_timestamp"));
                    assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
                    assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                    // Geo will fail on 127.0.0.1
                    assertEquals(
                        "unknown_ip_minfraud_geo_failure", a.getMetadataValue("state_action_type"));
                  }
                }
              }
              assertEquals(2L, newCnt);
              // Should have two informational since the rest of the duplicates will be
              // filtered in window since they were already seen
              assertEquals(2L, infoCnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeMixedIgnoreTest() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    Minfraud.cacheInsightsResource("216.160.83.56", "/testdata/minfraud/insights_normal1.json");
    Minfraud.cacheInsightsResource("127.0.0.1", "/testdata/minfraud/insights_normal1.json");
    options.setIgnoreUserRegex(new String[] {"^laforge@.*"});
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer2.txt", p);

    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                String actualSummary = a.getSummary();
                if (actualSummary.contains("new source")) {
                  newCnt++;
                } else {
                  infoCnt++;
                }
              }
              assertEquals(2L, newCnt);
              // Should have one informational since the rest of the duplicates will be
              // filtered in window since they were already seen
              assertEquals(1L, infoCnt);
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeGcpAlertIOIgnoreTest() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer5.txt", p);

    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long cnt = 0;
              for (Alert a : results) {
                // GCP origin and GcpAudit event, AlertIO ignore flag should be set
                assertEquals("true", a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                assertEquals("gcp_internal", a.getMetadataValue("state_action_type"));
                assertEquals("authprofile", a.getCategory());
                assertEquals(
                    "authentication event observed laforge@mozilla.com [untracked] to "
                        + "projects/test, 35.232.216.1 [unknown/unknown]",
                    a.getSummary());
                cnt++;
              }
              assertEquals(1L, cnt);
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeMixedIgnoreUnknownIdTest() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    Minfraud.cacheInsightsResource("216.160.83.56", "/testdata/minfraud/insights_normal1.json");
    Minfraud.cacheInsightsResource("127.0.0.1", "/testdata/minfraud/insights_normal1.json");
    options.setIgnoreUnknownIdentities(true);
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer2.txt", p);

    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                String actualSummary = a.getSummary();
                if (actualSummary.contains("new source")) {
                  newCnt++;
                } else {
                  infoCnt++;
                }
              }
              assertEquals(2L, newCnt);
              // Should have one informational since the rest of the duplicates will be
              // filtered in window since they were already seen
              assertEquals(1L, infoCnt);
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeNamedSubnetsTest() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    Minfraud.cacheInsightsResource(
        "fd00:0:0:0:0:0:0:1", "/testdata/minfraud/insights_normal1.json");
    Minfraud.cacheInsightsResource(
        "fd00:0:0:0:0:0:0:2", "/testdata/minfraud/insights_normal1.json");
    Minfraud.cacheInsightsResource(
        "aaaa:0:0:0:0:0:0:1", "/testdata/minfraud/insights_normal1.json");
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer3.txt", p);

    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                assertEquals("state_analyze", a.getMetadataValue("category"));
                assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                String actualSummary = a.getSummary();
                if (actualSummary.matches("(.*)new source fd00(.*)")) {
                  newCnt++;
                  assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                  assertNull(a.getMetadataValue("notify_email_direct"));
                  assertEquals(a.getMetadataValue("notify_slack_direct"), "wriker@mozilla.com");
                  assertEquals(a.getMetadataValue("alert_notification_type"), "slack_confirmation");
                  assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
                  assertEquals("office", a.getMetadataValue("entry_key"));
                  assertEquals(
                      "unknown_ip_minfraud_geo_failure", a.getMetadataValue("state_action_type"));
                } else if (actualSummary.matches("(.*)new source aaaa(.*)")) {
                  newCnt++;
                  assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                  assertNull(a.getMetadataValue("notify_email_direct"));
                  assertEquals(a.getMetadataValue("notify_slack_direct"), "wriker@mozilla.com");
                  assertEquals(a.getMetadataValue("alert_notification_type"), "slack_confirmation");
                  assertNull(a.getMetadataValue("entry_key"));
                  assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
                  assertEquals(
                      "unknown_ip_minfraud_geo_failure", a.getMetadataValue("state_action_type"));
                }
                assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                assertEquals("riker", a.getMetadataValue("username"));
                assertEquals("emit-bastion", a.getMetadataValue("object"));
                assertEquals("unknown", a.getMetadataValue("sourceaddress_city"));
                assertEquals("unknown", a.getMetadataValue("sourceaddress_country"));
                assertEquals("2018-09-18T22:15:38.000Z", a.getMetadataValue("event_timestamp"));
              }
              assertEquals(2L, newCnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeTestAuth0() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();

    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer6.txt", p);
    options.setEnableCritObjectAnalysis(false);
    options.setAuth0ClientIds(new String[] {"1234567890"});
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    Minfraud.cacheInsightsResource("216.160.83.56", "/testdata/minfraud/insights_normal1.json");
    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                String actualSummary = a.getSummary();
                if (actualSummary.equals(
                    "authentication event observed wriker@mozilla.com [wriker@mozilla.com] to www.enterprise.com, "
                        + "216.160.83.56 [Milton/US]")) {
                  infoCnt++;
                  assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                  assertNull(a.getMetadataValue("notify_email_direct"));
                  assertNull(a.getMetadataValue("escalate_to"));
                  assertEquals("known_ip", a.getMetadataValue("state_action_type"));
                } else if (actualSummary.equals(
                    "authentication event observed wriker@mozilla.com [wriker@mozilla.com] to www.enterprise.com, "
                        + "new source 216.160.83.56 [Milton/US]")) {
                  newCnt++;
                  assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                  // No previous state, GeoIP will fail
                  assertEquals(
                      "unknown_ip_minfraud_geo_failure", a.getMetadataValue("state_action_type"));
                }
                assertEquals("state_analyze", a.getMetadataValue("category"));
                assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                assertEquals("wriker@mozilla.com", a.getMetadataValue("username"));
                assertEquals("www.enterprise.com", a.getMetadataValue("object"));
                assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                assertEquals("Milton", a.getMetadataValue("sourceaddress_city"));
                assertEquals("US", a.getMetadataValue("sourceaddress_country"));
              }
              assertEquals(1L, newCnt);
              // Should have one informational since the rest of the duplicates will be
              // filtered in window since they were already seen
              assertEquals(1L, infoCnt);

              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeTestMaxDistance() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();

    // Preload mock data
    State state =
        new State(
            new DatastoreStateInterface(
                options.getDatastoreKind(), options.getDatastoreNamespace()));
    state.initialize();
    StateCursor<AuthStateModel> c = state.newCursor(AuthStateModel.class, true);
    AuthStateModel sm = new AuthStateModel("wriker@mozilla.com");
    DateTime n = new DateTime();
    DateTime oneDayAgo = n.minusHours(1);
    Double lat = 58.4162;
    Double lon = 15.6162;
    sm.updateEntry("89.160.20.128", oneDayAgo, lat, lon);
    sm.set(c, new PruningStrategyEntryAge());
    state.done();

    options.setEnableCritObjectAnalysis(false);
    // Tests will use minFraud cache, but we need some placeholder account here
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    Minfraud.cacheInsightsResource("89.160.20.112", "/testdata/minfraud/insights_normal1.json");
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer7.txt", p);
    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                if (a.getMetadataValue("category").equals("state_analyze")) {
                  assertEquals("authprofile", a.getCategory());
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                  String actualSummary = a.getSummary();
                  if (actualSummary.equals(
                      "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                          + "89.160.20.112 [Linköping/SE]")) {
                    infoCnt++;
                    assertEquals("89.160.20.112", a.getMetadataValue("sourceaddress"));
                    assertEquals("Linköping", a.getMetadataValue("sourceaddress_city"));
                    assertEquals("SE", a.getMetadataValue("sourceaddress_country"));
                    assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                    assertNull(a.getMetadataValue("notify_email_direct"));
                    assertNull(a.getMetadataValue("notify_slack_direct"));
                    assertNull(a.getMetadataValue("escalate_to"));
                  } else if (actualSummary.equals(
                      "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                          + "new source 89.160.20.112 [Linköping/SE]")) {
                    newCnt++;
                    assertEquals("89.160.20.112", a.getMetadataValue("sourceaddress"));
                    assertEquals("Linköping", a.getMetadataValue("sourceaddress_city"));
                    assertEquals("SE", a.getMetadataValue("sourceaddress_country"));
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertEquals("wriker@mozilla.com", a.getMetadataValue("notify_email_direct"));
                    assertNull(a.getMetadataValue("notify_slack_direct"));
                    assertEquals("false", a.getMetadataValue("sourceaddress_is_anonymous"));
                    assertEquals("false", a.getMetadataValue("sourceaddress_is_anonymous_vpn"));
                    assertEquals("false", a.getMetadataValue("sourceaddress_is_hosting_provider"));
                    assertEquals("unknown_ip_within_geo", a.getMetadataValue("state_action_type"));
                  }
                }
              }
              assertEquals(1L, newCnt);
              // Should have one informational since the rest of the duplicates will be
              // filtered in window since they were already seen
              assertEquals(1L, infoCnt);

              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeTestMinfraudHosting() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();

    // Preload mock data
    State state =
        new State(
            new DatastoreStateInterface(
                options.getDatastoreKind(), options.getDatastoreNamespace()));
    state.initialize();
    StateCursor<AuthStateModel> c = state.newCursor(AuthStateModel.class, true);
    AuthStateModel sm = new AuthStateModel("wriker@mozilla.com");
    DateTime n = new DateTime();
    DateTime oneDayAgo = n.minusHours(1);
    Double lat = 58.4162;
    Double lon = 15.6162;
    sm.updateEntry("89.160.20.128", oneDayAgo, lat, lon);
    sm.set(c, new PruningStrategyEntryAge());
    state.done();

    options.setEnableCritObjectAnalysis(false);
    // Tests will use minFraud cache, but we need some placeholder account here
    options.setMaxmindAccountId("0");
    options.setMaxmindLicenseKey("something");
    Minfraud.cacheInsightsResource("89.160.20.112", "/testdata/minfraud/insights_hosting1.json");
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer7.txt", p);
    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                if (a.getMetadataValue("category").equals("state_analyze")) {
                  assertEquals("authprofile", a.getCategory());
                  assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                  assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                  assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                  String actualSummary = a.getSummary();
                  if (actualSummary.equals(
                      "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                          + "89.160.20.112 [Linköping/SE]")) {
                    infoCnt++;
                    assertEquals("89.160.20.112", a.getMetadataValue("sourceaddress"));
                    assertEquals("Linköping", a.getMetadataValue("sourceaddress_city"));
                    assertEquals("SE", a.getMetadataValue("sourceaddress_country"));
                    assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                    assertNull(a.getMetadataValue("notify_email_direct"));
                    assertNull(a.getMetadataValue("notify_slack_direct"));
                    assertNull(a.getMetadataValue("escalate_to"));
                  } else if (actualSummary.equals(
                      "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                          + "new source 89.160.20.112 [Linköping/SE]")) {
                    newCnt++;
                    assertEquals("89.160.20.112", a.getMetadataValue("sourceaddress"));
                    assertEquals("Linköping", a.getMetadataValue("sourceaddress_city"));
                    assertEquals("SE", a.getMetadataValue("sourceaddress_country"));
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertNull(a.getMetadataValue("notify_email_direct"));
                    assertEquals("wriker@mozilla.com", a.getMetadataValue("notify_slack_direct"));
                    assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
                    assertEquals("false", a.getMetadataValue("sourceaddress_is_anonymous"));
                    assertEquals("false", a.getMetadataValue("sourceaddress_is_anonymous_vpn"));
                    assertEquals("true", a.getMetadataValue("sourceaddress_is_hosting_provider"));
                    assertEquals(
                        "unknown_ip_hosting_provider", a.getMetadataValue("state_action_type"));
                  }
                }
              }
              assertEquals(1L, newCnt);
              // Should have one informational since the rest of the duplicates will be
              // filtered in window since they were already seen
              assertEquals(1L, infoCnt);

              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void templateRender() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"eca99844-96ac-4a44-adba-48ce3c593157\","
            + "\"summary\":\"authentication event observed riker [wriker@mozilla.com] "
            + "to emit-bastion, 216.160.83.56 [Milton/US]\",\"category\":\"authprofile"
            + "\",\"payload\":\"An authentication event for user riker was detected to"
            + " access emit-bastion from 216.160.83.56 [Milton/US]. This occurred from "
            + "a known source address.\\n\\nIf this was not you, or you have any question"
            + "s about this alert, email us at secops@mozilla.com with the alert id.\","
            + "\"timestamp\":\"2019-12-17T19:48:18.680Z\",\"metadata\":[{\"key\":\"obje"
            + "ct\",\"value\":\"emit-bastion\"},{\"key\":\"username\",\"value\":\"riker"
            + "\"},{\"key\":\"sourceaddress\",\"value\":\"216.160.83.56\"},{\"key\":\"e"
            + "mail_contact\",\"value\":\"test@localhost\"},{\"key\":\"doc_link\",\"val"
            + "ue\":\"https://localhost\"},{\"key\":\"template_name_email\",\"value\":"
            + "\"email/authprofile.ftlh\"},{\"key\":\"template_name_slack\",\"value\":"
            + "\"slack/authprofile.ftlh\"},{\"key\":\"sourceaddress_city\",\"value\":\""
            + "Milton\"},{\"key\":\"sourceaddress_country\",\"value\":\"US\"},{\"key\":"
            + "\"sourceaddress_timezone\",\"value\":\"America/Los_Angeles\"},{\"key\":"
            + "\"auth_alert_type\",\"value\":\"auth\"},{\"key\":\"event_timestamp\",\""
            + "value\":\"2018-09-18T22:15:38.000Z\"},{\"key\":\"event_timestamp_source"
            + "_local\",\"value\":\"2018-09-18T15:15:38.000-07:00\"},{\"key\":\"catego"
            + "ry\",\"value\":\"state_analyze\"},{\"key\":\"identity_key\",\"value\":"
            + "\"wriker@mozilla.com\"},{\"key\":\"state_action_type\",\"value\":\"known_ip\"}]}";

    Alert a = Alert.fromJSON(buf);
    assertNotNull(a);

    AlertConfiguration alertCfg = new AlertConfiguration();
    alertCfg.registerTemplate("email/authprofile.ftlh");
    alertCfg.registerTemplate("slack/authprofile.ftlh");
    TemplateManager tmgr = new TemplateManager(alertCfg);
    tmgr.validate();
    String templateOutput =
        tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
    assertEquals(
        "known ip",
        renderTestTemplate("/testdata/templateoutput/email/authprof_state_known.html", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_MINFRAUD_GEO_FAILURE.toString());
    templateOutput = tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip no geo",
        renderTestTemplate("/testdata/templateoutput/email/authprof_state_new.html", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_WITHIN_GEO.toString());
    templateOutput = tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip within geo",
        renderTestTemplate("/testdata/templateoutput/email/authprof_state_new_within_geo.html", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_OUTSIDE_GEO.toString());
    templateOutput = tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip outside geo",
        renderTestTemplate("/testdata/templateoutput/email/authprof_state_new_outside_geo.html", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_HOSTING_PROVIDER.toString());
    templateOutput = tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip hosting",
        renderTestTemplate("/testdata/templateoutput/email/authprof_state_new_hosting.html", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_ANON_NETWORK.toString());
    templateOutput = tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip anon",
        renderTestTemplate("/testdata/templateoutput/email/authprof_state_new_anon.html", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_WITHIN_GEO.toString());
    a.setMetadataValue("alert_notification_type", "slack_notification");
    templateOutput = tmgr.processTemplate(a.getSlackTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip within geo slack",
        renderTestTemplate("/testdata/templateoutput/slack/authprof_state_new_within_geo.txt", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_OUTSIDE_GEO.toString());
    a.setMetadataValue("alert_notification_type", "slack_confirmation");
    templateOutput = tmgr.processTemplate(a.getSlackTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip outside geo slack",
        renderTestTemplate("/testdata/templateoutput/slack/authprof_state_new_outside_geo.txt", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_HOSTING_PROVIDER.toString());
    templateOutput = tmgr.processTemplate(a.getSlackTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip hosting slack",
        renderTestTemplate("/testdata/templateoutput/slack/authprof_state_new_hosting.txt", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_ANON_NETWORK.toString());
    templateOutput = tmgr.processTemplate(a.getSlackTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip anon slack",
        renderTestTemplate("/testdata/templateoutput/slack/authprof_state_new_anon.txt", a),
        templateOutput);

    a.setMetadataValue(
        AuthProfile.StateAnalyze.META_ACTION_TYPE,
        AuthProfile.StateAnalyze.ActionType.UNKNOWN_IP_MINFRAUD_GEO_FAILURE.toString());
    templateOutput = tmgr.processTemplate(a.getSlackTemplate(), a.generateTemplateVariables());
    assertEquals(
        "unknown ip no geo slack",
        renderTestTemplate("/testdata/templateoutput/slack/authprof_state_new.txt", a),
        templateOutput);
  }
}
