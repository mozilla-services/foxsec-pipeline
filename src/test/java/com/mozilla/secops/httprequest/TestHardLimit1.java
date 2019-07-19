package com.mozilla.secops.httprequest;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.TestIprepdIO;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import java.util.Map;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

/**
 * HTTPRequest hard limit transform tests
 *
 * <p>Note we also test some IprepdIO submission and IP whitelisting here.
 */
public class TestHardLimit1 {
  @Rule public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

  public TestHardLimit1() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private void testEnv() throws Exception {
    environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
    environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
    environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
    environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
  }

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setHardLimitRequestCount(10L);
    ret.setMonitoredResourceIndicator("test");
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void hardLimitTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_hardlimit1.txt", p);

    TestIprepdIO.deleteReputation("ip", "192.168.1.1");
    TestIprepdIO.deleteReputation("ip", "192.168.1.2");
    TestIprepdIO.deleteReputation("ip", "192.168.1.3");
    TestIprepdIO.deleteReputation("ip", "192.168.1.4");

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080", "test", null);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setOutputIprepd("http://127.0.0.1:8080");
    options.setOutputIprepdApikey("test");

    PCollection<Alert> results =
        input
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.WindowForFixed())
            .apply(new HTTPRequest.HardLimitAnalysis(options));

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    results
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(OutputOptions.compositeOutput(options));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .isEqualTo(2L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertThat(
                    a.getMetadataValue("sourceaddress"),
                    anyOf(equalTo("192.168.1.2"), equalTo("192.168.1.4")));
                String summary =
                    String.format(
                        "test httprequest hard_limit %s 11", a.getMetadataValue("sourceaddress"));
                assertEquals(summary, a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue("count")));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("request_threshold")));
                assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.4"));

    p.run().waitUntilFinish();

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.4"));
  }

  @Test
  public void hardLimitTestDatastoreIprepdWhitelist() throws Exception {
    testEnv();

    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_hardlimit1.txt", p);

    TestIprepdIO.deleteReputation("ip", "192.168.1.1");
    TestIprepdIO.deleteReputation("ip", "192.168.1.2");
    TestIprepdIO.deleteReputation("ip", "192.168.1.3");
    TestIprepdIO.deleteReputation("ip", "192.168.1.4");

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080", "test", null);

    State state =
        new State(
            new DatastoreStateInterface(
                IprepdIO.whitelistedIpKind, IprepdIO.whitelistedIpNamespace));
    state.initialize();

    IprepdIO.WhitelistedIp wip = new IprepdIO.WhitelistedIp();
    wip.setIp("192.168.1.4");
    wip.setExpiresAt(new DateTime().plusDays(1));
    wip.setCreatedBy("test");

    StateCursor cur = state.newCursor();
    cur.set("192.168.1.4", wip);
    cur.commit();
    state.done();

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setOutputIprepdEnableDatastoreWhitelist(true);
    options.setOutputIprepd("http://127.0.0.1:8080");
    options.setOutputIprepdApikey("test");

    PCollection<Alert> results =
        input
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.WindowForFixed())
            .apply(new HTTPRequest.HardLimitAnalysis(options));

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    results
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(OutputOptions.compositeOutput(options));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .isEqualTo(2L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertThat(
                    a.getMetadataValue("sourceaddress"),
                    anyOf(equalTo("192.168.1.2"), equalTo("192.168.1.4")));
                String summary =
                    String.format(
                        "test httprequest hard_limit %s 11", a.getMetadataValue("sourceaddress"));
                assertEquals(summary, a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue("count")));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("request_threshold")));
                assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.4"));

    p.run().waitUntilFinish();

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.4"));
  }

  @Test
  public void hardLimitTestWithNatDetect() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_hardlimit1.txt", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    PCollection<Event> events =
        input.apply(new HTTPRequest.Parse(options)).apply(new HTTPRequest.WindowForFixed());

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Alert> results = events.apply(new HTTPRequest.HardLimitAnalysis(options, natView));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .isEqualTo(1L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                assertEquals("test httprequest hard_limit 192.168.1.2 11", a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue("count")));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("request_threshold")));
                assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
