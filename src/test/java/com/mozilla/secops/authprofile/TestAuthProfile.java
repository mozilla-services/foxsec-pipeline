package com.mozilla.secops.authprofile;

import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import java.util.Collection;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

public class TestAuthProfile {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

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
    return ret;
  }

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

  @Test
  public void parseAndWindowTest() throws Exception {
    testEnv();
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer1.txt", p);

    PCollection<KV<String, Iterable<Event>>> res =
        input.apply(new AuthProfile.ParseAndWindow(getTestOptions()));
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
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer1.txt", p);

    PCollection<Alert> res =
        input
            .apply(new AuthProfile.ParseAndWindow(options))
            .apply(ParDo.of(new AuthProfile.Analyze(options)));

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
                String actualSummary = a.getSummary();
                if (actualSummary.equals(
                    "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                        + "216.160.83.56 [Milton/US]")) {
                  infoCnt++;
                  assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                  assertNull(a.getTemplateName());
                  assertNull(a.getMetadataValue("notify_email_direct"));
                } else if (actualSummary.equals(
                    "authentication event observed riker [wriker@mozilla.com] to emit-bastion, "
                        + "new source 216.160.83.56 [Milton/US]")) {
                  newCnt++;
                  assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                  assertEquals("authprofile.ftlh", a.getTemplateName());
                  assertEquals(
                      "holodeck-riker@mozilla.com", a.getMetadataValue("notify_email_direct"));
                }
                assertEquals("wriker@mozilla.com", a.getMetadataValue("identity_key"));
                assertEquals("riker", a.getMetadataValue("username"));
                assertEquals("emit-bastion", a.getMetadataValue("object"));
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
  public void analyzeMixedTest() throws Exception {
    testEnv();
    AuthProfile.AuthProfileOptions options = getTestOptions();
    PCollection<String> input = TestUtil.getTestInput("/testdata/authprof_buffer2.txt", p);

    PCollection<Alert> res =
        input
            .apply(new AuthProfile.ParseAndWindow(options))
            .apply(ParDo.of(new AuthProfile.Analyze(options)));

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
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
                } else if ((iKey != null) && (iKey.equals("wriker@mozilla.com"))) {
                  if (a.getMetadataValue("username").equals("riker@mozilla.com")) {
                    // GcpAudit event should have generated a warning
                    assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    assertEquals(
                        "holodeck-riker@mozilla.com", a.getMetadataValue("notify_email_direct"));
                    assertEquals("authprofile.ftlh", a.getTemplateName());
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

    PCollection<Alert> res =
        input
            .apply(new AuthProfile.ParseAndWindow(options))
            .apply(ParDo.of(new AuthProfile.Analyze(options)));

    PAssert.that(res)
        .satisfies(
            results -> {
              long newCnt = 0;
              long infoCnt = 0;
              for (Alert a : results) {
                assertEquals("authprofile", a.getCategory());
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
}
