package com.mozilla.secops.httprequest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;

import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.TestIprepdIO;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.heuristics.HardLimitAnalysis;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import org.apache.beam.sdk.PipelineResult;
import org.apache.beam.sdk.metrics.MetricNameFilter;
import org.apache.beam.sdk.metrics.MetricResult;
import org.apache.beam.sdk.metrics.MetricsFilter;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

/**
 * HTTPRequest hard limit transform tests
 *
 * <p>Note we also test some IprepdIO submission and IP exemptions here.
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
    ret.setEnableHardLimitAnalysis(true);
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    ret.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_hardlimit1.txt"});
    return ret;
  }

  @Test
  public void hardLimitTest() throws Exception {
    TestIprepdIO.deleteReputation("ip", "192.168.1.1");
    TestIprepdIO.deleteReputation("ip", "192.168.1.2");
    TestIprepdIO.deleteReputation("ip", "192.168.1.3");
    TestIprepdIO.deleteReputation("ip", "192.168.1.4");
    TestIprepdIO.deleteReputation("ip", "192.168.1.5");

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080|test", null);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setOutputIprepd(new String[] {"http://127.0.0.1:8080|test"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    results
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(MapElements.via(new AlertFormatter.AlertToString()))
        .apply(OutputOptions.compositeOutput(options));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount).isEqualTo(3L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertThat(
                    a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS),
                    anyOf(equalTo("192.168.1.2"), equalTo("192.168.1.4"), equalTo("192.168.1.5")));
                String summary =
                    String.format(
                        "test httprequest hard_limit %s 11",
                        a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(summary, a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT)));
                assertEquals(
                    10L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.REQUEST_THRESHOLD)));
                assertEquals(
                    "1970-01-01T00:00:59.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
              }
              return null;
            });

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.4"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.5"));

    p.run().waitUntilFinish();

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.4"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.5"));
  }

  @Test
  public void hardLimitTestDatastoreIprepdExemptions() throws Exception {
    testEnv();

    TestIprepdIO.deleteReputation("ip", "192.168.1.1");
    TestIprepdIO.deleteReputation("ip", "192.168.1.2");
    TestIprepdIO.deleteReputation("ip", "192.168.1.3");
    TestIprepdIO.deleteReputation("ip", "192.168.1.4");
    TestIprepdIO.deleteReputation("ip", "192.168.1.5");

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080|test", null);

    // Create exempted ip in datastore
    State state =
        new State(
            new DatastoreStateInterface(IprepdIO.exemptedIpKind, IprepdIO.exemptedObjectNamespace));
    state.initialize();
    IprepdIO.ExemptedObject wobj = new IprepdIO.ExemptedObject();
    wobj.setObject("192.168.1.4");
    wobj.setType("ip");
    wobj.setExpiresAt(new DateTime().plusDays(1));
    wobj.setCreatedBy("test");
    StateCursor<IprepdIO.ExemptedObject> cur =
        state.newCursor(IprepdIO.ExemptedObject.class, false);
    cur.set("192.168.1.4", wobj);
    state.done();

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setOutputIprepdEnableDatastoreExemptions(true);
    options.setOutputIprepd(new String[] {"http://127.0.0.1:8080|test"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    results
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(MapElements.via(new AlertFormatter.AlertToString()))
        .apply(OutputOptions.compositeOutput(options));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount).isEqualTo(3L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertThat(
                    a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS),
                    anyOf(equalTo("192.168.1.2"), equalTo("192.168.1.4"), equalTo("192.168.1.5")));
                String summary =
                    String.format(
                        "test httprequest hard_limit %s 11",
                        a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(summary, a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT)));
                assertEquals(
                    10L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.REQUEST_THRESHOLD)));
                assertEquals(
                    "1970-01-01T00:00:59.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
              }
              return null;
            });

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.4"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.5"));

    p.run().waitUntilFinish();

    assertEquals(100, (int) r.getReputation("ip", "192.168.1.1"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.2"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.3"));
    assertEquals(100, (int) r.getReputation("ip", "192.168.1.4"));
    assertEquals(90, (int) r.getReputation("ip", "192.168.1.5"));
  }

  @Test
  public void hardLimitTestWithNatDetect() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setNatDetection(true);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals("test httprequest hard_limit 192.168.1.2 11", a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT)));
                assertEquals(
                    10L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.REQUEST_THRESHOLD)));
                assertEquals(
                    "1970-01-01T00:00:59.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
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
                            HardLimitAnalysis.class.getName(),
                            HTTPRequestMetrics.HeuristicMetrics.NAT_DETECTED))
                    .build())
            .getCounters();
    int cnt = 0;
    for (MetricResult<Long> x : vWrites) {
      assertEquals(2L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);
  }
}
