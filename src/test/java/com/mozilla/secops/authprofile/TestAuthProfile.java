package com.mozilla.secops.authprofile;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertConfiguration;
import com.mozilla.secops.alert.AlertIO;
import com.mozilla.secops.alert.TemplateManager;
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
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
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

    DateTimeFormatter fmt = DateTimeFormat.forPattern("MMM d, yyyy h:mm:ss aa");
    in = in.replaceAll("DATESTAMP", fmt.print(a.getTimestamp()));
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
  }

  private AuthProfile.AuthProfileOptions getTestOptions() {
    AuthProfile.AuthProfileOptions ret =
        PipelineOptionsFactory.as(AuthProfile.AuthProfileOptions.class);
    ret.setDatastoreNamespace("testauthprofileanalyze");
    ret.setDatastoreKind("authprofile");
    ret.setIdentityManagerPath("/testdata/identitymanager.json");
    ret.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    return ret;
  }

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

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

    // Enable configuration tick generation in the pipeline for this test, and use CompositeInput
    options.setInputFile(new String[] {"./target/test-classes/testdata/authprof_buffer1.txt"});
    options.setGenerateConfigurationTicksInterval(1);
    options.setGenerateConfigurationTicksMaximum(5L);
    options.setEnableCritObjectAnalysis(false);
    PCollection<String> input =
        p.apply(
            "input",
            new CompositeInput(
                (InputOptions) options, AuthProfile.buildConfigurationTick(options)));

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
                    infoCnt++;
                    assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                    assertNull(a.getMetadataValue("notify_email_direct"));
                    assertNull(a.getMetadataValue("escalate_to"));

                    // Verify sample rendered email template for known source
                    try {
                      AlertConfiguration alertCfg = new AlertConfiguration();
                      alertCfg.registerTemplate("email/authprofile.ftlh");
                      TemplateManager tmgr = new TemplateManager(alertCfg);
                      tmgr.validate();
                      String templateOutput =
                          tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
                      assertEquals(
                          renderTestTemplate(
                              "/testdata/templateoutput/authprof_state_known.html", a),
                          templateOutput);
                    } catch (Exception exc) {
                      fail(exc.getMessage());
                    }
                  } else if (actualSummary.equals(
                      "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                          + "new source 216.160.83.56 [Milton/US]")) {
                    newCnt++;
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertEquals(
                        "holodeck-riker@mozilla.com", a.getMetadataValue("notify_email_direct"));
                    assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));

                    // Verify sample rendered email template for new source
                    try {
                      TemplateManager tmgr = new TemplateManager(new AlertConfiguration());
                      tmgr.validate();
                      String templateOutput =
                          tmgr.processTemplate(a.getEmailTemplate(), a.generateTemplateVariables());
                      assertEquals(
                          renderTestTemplate("/testdata/templateoutput/authprof_state_new.html", a),
                          templateOutput);
                    } catch (Exception exc) {
                      fail(exc.getMessage());
                    }
                  }
                  assertEquals("state_analyze", a.getMetadataValue("category"));
                  assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                  assertEquals("riker", a.getMetadataValue("username"));
                  assertEquals("emit-bastion", a.getMetadataValue("object"));
                  assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                  assertEquals("Milton", a.getMetadataValue("sourceaddress_city"));
                  assertEquals("US", a.getMetadataValue("sourceaddress_country"));
                  assertEquals("2018-09-18T22:15:38.000Z", a.getMetadataValue("event_timestamp"));
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
                assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
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
                  assertThat(a.getSummary(), containsString("untracked"));
                  assertEquals("2019-01-03T20:52:04.782Z", a.getMetadataValue("event_timestamp"));
                } else if ((iKey != null) && (iKey.equals("wriker@mozilla.com"))) {
                  if (a.getMetadataValue("username").equals("riker@mozilla.com")) {
                    // GcpAudit event should have generated a warning
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertEquals(
                        "holodeck-riker@mozilla.com", a.getMetadataValue("notify_email_direct"));
                    assertEquals("email/authprofile.ftlh", a.getEmailTemplate());
                    assertEquals("slack/authprofile.ftlh", a.getSlackTemplate());
                    assertEquals("2019-01-03T20:52:04.782Z", a.getMetadataValue("event_timestamp"));
                    assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
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
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer5.txt", p);

    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              long cnt = 0;
              for (Alert a : results) {
                // GCP origin and GcpAudit event, AlertIO ignore flag should be set
                assertEquals("true", a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
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
                  assertEquals(
                      "holodeck-riker@mozilla.com", a.getMetadataValue("notify_email_direct"));
                  assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
                  assertEquals("office", a.getMetadataValue("entry_key"));
                } else if (actualSummary.matches("(.*)new source aaaa(.*)")) {
                  newCnt++;
                  assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                  assertEquals(
                      "holodeck-riker@mozilla.com", a.getMetadataValue("notify_email_direct"));
                  assertNull(a.getMetadataValue("entry_key"));
                  assertEquals("picard@mozilla.com", a.getMetadataValue("escalate_to"));
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
  public void analyzeTestGeoVelocityAlert() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();
    // Set a low `maxKilometersPerSecond`
    options.setMaximumKilometersPerHour(1);

    PCollection<String> input =
        TestUtil.getTestInput("/testdata/authprof_geovelocity_buffer1.txt", p);
    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PAssert.that(res)
        .satisfies(
            results -> {
              int geoAlert = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                assertEquals("riker", a.getMetadataValue("username"));
                assertEquals("emit-bastion", a.getMetadataValue("object"));
                String actualSummary = a.getSummary();
                if (actualSummary.contains("geovelocity anomaly detected on authentication event")
                    && actualSummary.contains("81.2.69.192")) {
                  geoAlert++;
                  assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                  assertNull(a.getMetadataValue("notify_email_direct"));
                  assertNull(a.getMetadataValue("escalate_to"));
                  assertEquals("geo_velocity", a.getMetadataValue("category"));
                  assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                }
              }
              assertEquals(1, geoAlert);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeTestGeoVelocityAlertDefaults() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();

    // Preload mock data
    State state =
        new State(
            new DatastoreStateInterface(
                options.getDatastoreKind(), options.getDatastoreNamespace()));
    state.initialize();
    StateCursor c = state.newCursor();
    StateModel sm = new StateModel("wriker@mozilla.com");
    DateTime n = new DateTime();
    // Set it to be a day ago so that we can test that moving a new entry far away
    // geographically in a long period of time does not create an alert.
    DateTime oneDayAgo = n.minusHours(24);
    Double lat = 47.2513;
    Double lon = -122.3149;
    sm.updateEntry("216.160.83.56", oneDayAgo, lat, lon);
    sm.set(c);
    state.done();

    PCollection<String> input =
        TestUtil.getTestInput("/testdata/authprof_geovelocity_buffer2.txt", p);
    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PCollection<Long> count = res.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(3L);

    PAssert.that(res)
        .satisfies(
            results -> {
              int geoAlert = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                assertEquals("riker", a.getMetadataValue("username"));
                assertEquals("emit-bastion", a.getMetadataValue("object"));
                String actualSummary = a.getSummary();
                if (actualSummary.contains(
                    "geovelocity anomaly detected on authentication event")) {
                  geoAlert++;
                  assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                  assertNull(a.getMetadataValue("notify_email_direct"));
                  assertNull(a.getMetadataValue("escalate_to"));
                  assertEquals("geo_velocity", a.getMetadataValue("category"));
                  assertNull(a.getMetadataValue(AlertIO.ALERTIO_IGNORE_EVENT));
                }
              }
              assertEquals(1, geoAlert);
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void analyzeTestGeoVelocityIgnoresOldStateEntries() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();

    // Preload mock data with no lat/lon
    State state =
        new State(
            new DatastoreStateInterface(
                options.getDatastoreKind(), options.getDatastoreNamespace()));
    state.initialize();
    StateCursor c = state.newCursor();
    StateModel sm = new StateModel("wriker@mozilla.com");
    sm.updateEntry("216.160.83.56", null, null);
    sm.set(c);
    state.done();

    PCollection<String> input =
        TestUtil.getTestInput("/testdata/authprof_geovelocity_buffer3.txt", p);
    PCollection<Alert> res = AuthProfile.processInput(input, options);

    PCollection<Long> count = res.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(1L);

    PAssert.that(res)
        .satisfies(
            results -> {
              int geoAlert = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                assertEquals("riker", a.getMetadataValue("username"));
                assertEquals("emit-bastion", a.getMetadataValue("object"));
                String actualSummary = a.getSummary();
                if (actualSummary.contains(
                    "geovelocity anomaly detected on authentication event")) {
                  geoAlert++;
                }
              }
              assertEquals(0, geoAlert);
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
                } else if (actualSummary.equals(
                    "authentication event observed wriker@mozilla.com [wriker@mozilla.com] to www.enterprise.com, "
                        + "new source 216.160.83.56 [Milton/US]")) {
                  newCnt++;
                  assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
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
}
