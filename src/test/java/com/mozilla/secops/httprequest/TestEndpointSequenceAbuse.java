package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.heuristics.EndpointSequenceAbuse;
import org.apache.beam.sdk.PipelineResult;
import org.apache.beam.sdk.metrics.MetricNameFilter;
import org.apache.beam.sdk.metrics.MetricResult;
import org.apache.beam.sdk.metrics.MetricsFilter;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestEndpointSequenceAbuse {
  public TestEndpointSequenceAbuse() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setMonitoredResourceIndicator("test");
    ret.setEnableEndpointSequenceAbuseAnalysis(true);
    ret.setSessionGapDurationMinutes(20L);
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    ret.setIgnoreCloudProviderRequests(false);
    return ret;
  }

  @Test
  public void SingleViolationEventsReceivedInOrder() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse1.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("1970-01-01T00:00:00.010Z", a.getTimestamp().toString());
                assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest endpoint_sequence_abuse 192.168.1.2 GET:/test:1000:GET:/test2 1",
                    a.getSummary());
                assertEquals("test endpoint_sequence_abuse", a.getNotifyMergeKey());
                assertEquals(
                    "endpoint_sequence_abuse",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                assertEquals("Mozilla", a.getMetadataValue(AlertMeta.Key.USERAGENT));
                assertEquals(1L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
              }
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void SingleViolationEventsReceivedOutOfOrder() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse2.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("1970-01-01T00:00:00.010Z", a.getTimestamp().toString());
                assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest endpoint_sequence_abuse 192.168.1.2 GET:/test:1000:GET:/test2 1",
                    a.getSummary());
                assertEquals("test endpoint_sequence_abuse", a.getNotifyMergeKey());
                assertEquals(
                    "endpoint_sequence_abuse",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                assertEquals("Mozilla", a.getMetadataValue(AlertMeta.Key.USERAGENT));
                assertEquals(1L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
              }
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void MultipleViolationsAlertsOnMax() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[2];
    v[0] = "1:GET:/test:1000:GET:/test2";
    v[1] = "1:GET:/test3:1000:GET:/test4";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse3.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("1970-01-01T00:00:10.500Z", a.getTimestamp().toString());
                assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest endpoint_sequence_abuse 192.168.1.2 GET:/test:1000:GET:/test2 2",
                    a.getSummary());
                assertEquals("test endpoint_sequence_abuse", a.getNotifyMergeKey());
                assertEquals(
                    "endpoint_sequence_abuse",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                assertEquals("Mozilla", a.getMetadataValue(AlertMeta.Key.USERAGENT));
                assertEquals(2L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
              }
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void NoViolationsWhenSequenceIsOutOfOrder() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse4.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(0L);
    p.run().waitUntilFinish();
  }

  @Test
  public void NoViolationsWhenSequenceIsSplitBetweenWindows() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse5.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(0L);
    p.run().waitUntilFinish();
  }

  @Test
  public void NoViolationsWhenFirstMethodDoesNotMatch() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:POST:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse1.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(0L);
    p.run().waitUntilFinish();
  }

  @Test
  public void NoViolationsWhenSecondMethodDoesNotMatch() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:POST:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse1.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(0L);
    p.run().waitUntilFinish();
  }

  @Test
  public void NoViolationsWhenBothMethodsDoNotMatch() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:POST:/test:1000:POST:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse1.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(0L);
    p.run().waitUntilFinish();
  }

  @Test
  public void NoViolationsWhenRequestSequenceIsNotWithinDelta() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse4.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(0L);
    p.run().waitUntilFinish();
  }

  @Test
  public void MultipleIPsWithViolations() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse8.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(2L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS).equals("192.168.1.2")) {
                  assertEquals("1970-01-01T00:00:00.010Z", a.getTimestamp().toString());
                  assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals(
                      "test httprequest endpoint_sequence_abuse 192.168.1.2 GET:/test:1000:GET:/test2 1",
                      a.getSummary());
                  assertEquals("test endpoint_sequence_abuse", a.getNotifyMergeKey());
                  assertEquals(
                      "endpoint_sequence_abuse",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                  assertEquals("Mozilla", a.getMetadataValue(AlertMeta.Key.USERAGENT));
                  assertEquals(1L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                } else if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS).equals("192.168.1.3")) {
                  assertEquals("1970-01-01T00:00:00.040Z", a.getTimestamp().toString());
                  assertEquals("192.168.1.3", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals(
                      "test httprequest endpoint_sequence_abuse 192.168.1.3 GET:/test:1000:GET:/test2 1",
                      a.getSummary());
                  assertEquals("test endpoint_sequence_abuse", a.getNotifyMergeKey());
                  assertEquals(
                      "endpoint_sequence_abuse",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                  assertEquals("Mozilla", a.getMetadataValue(AlertMeta.Key.USERAGENT));
                  assertEquals(1L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                }
              }
              return null;
            });
    p.run().waitUntilFinish();
  }

  @Test
  public void NoViolationsWhenEndpointIsSuspectedNAT() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setNatDetection(true);

    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse9.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PAssert.that(results).empty();

    PipelineResult pResult = p.run();
    pResult.waitUntilFinish();

    Iterable<MetricResult<Long>> vWrites =
        pResult
            .metrics()
            .queryMetrics(
                MetricsFilter.builder()
                    .addNameFilter(
                        MetricNameFilter.named(
                            EndpointSequenceAbuse.class.getName(),
                            HTTPRequestMetrics.HeuristicMetrics.NAT_DETECTED))
                    .build())
            .getCounters();
    int cnt = 0;
    for (MetricResult<Long> x : vWrites) {
      assertEquals(1L, (long) x.getCommitted());
      cnt++;
    }
    assertEquals(1, cnt);
  }

  @Test
  public void ViolationDetectedInMixedEventWindow() throws Exception {

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "1:GET:/test:1000:GET:/test2";
    options.setEndpointSequenceAbusePatterns(v);
    options.setEndpointSequenceAbuseSuppressRecovery(60);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_endpointsequenceabuse10.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("1970-01-01T00:00:00.010Z", a.getTimestamp().toString());
                assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest endpoint_sequence_abuse 192.168.1.2 GET:/test:1000:GET:/test2 1",
                    a.getSummary());
                assertEquals("test endpoint_sequence_abuse", a.getNotifyMergeKey());
                assertEquals(
                    "endpoint_sequence_abuse",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                assertEquals("Mozilla", a.getMetadataValue(AlertMeta.Key.USERAGENT));
                assertEquals(1L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
              }
              return null;
            });
    p.run().waitUntilFinish();
  }
}
