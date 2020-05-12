package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestPerEndpointErrorRateAnalysis {

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setMonitoredResourceIndicator("test");
    ret.setEnablePerEndpointErrorRateAnalysis(true);
    ret.setErrorSessionGapDurationMinutes(1L);
    ret.setPerEndpointErrorRateAlertSuppressionDurationSeconds(20L);
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void perEndpointErrorRateTestStream() throws Exception {
    // this test case contains: IPs that do not make enough bad requests to trigger alert,
    // ips that don't make enough bad GET requests, but do if you wrongly include POST requests,
    // ip that triggers alert with violations all in one pane, and an ip that triggers alert
    // with events between two panes. Requests match one endpoint.
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate1/httpreq_perendpointerrorrate1_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate1/httpreq_perendpointerrorrate1_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate1/httpreq_perendpointerrorrate1_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "4:GET:/test";
    options.setPerEndpointErrorRatePaths(v);
    options.setPerEndpointErrorRateAnalysisSuppressRecovery(60);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(15)))
            .advanceProcessingTime(Duration.standardSeconds(15))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(45)))
            .advanceProcessingTime(Duration.standardSeconds(30))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(1L, 1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              int ip1Count = 0;
              int ip2Count = 0;
              for (Alert a : i) {
                if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS).equals("192.168.1.2")) {
                  assertEquals("1970-01-01T00:00:00.000Z", a.getTimestamp().toString());
                  assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals(
                      "test httprequest per_endpoint_error_rate 192.168.1.2 GET /test 5",
                      a.getSummary());
                  assertEquals("test per_endpoint_error_rate", a.getNotifyMergeKey());
                  assertEquals(
                      "per_endpoint_error_rate",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                  assertEquals(5L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                  assertEquals(
                      "1970-01-01T00:00:59.999Z",
                      a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                  ip2Count++;
                } else if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS).equals("192.168.1.1")) {
                  assertEquals("1970-01-01T00:00:45.000Z", a.getTimestamp().toString());
                  assertEquals("192.168.1.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals(
                      "test httprequest per_endpoint_error_rate 192.168.1.1 GET /test 5",
                      a.getSummary());
                  assertEquals("test per_endpoint_error_rate", a.getNotifyMergeKey());
                  assertEquals(
                      "per_endpoint_error_rate",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                  assertEquals(5L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                  assertEquals(
                      "1970-01-01T00:01:44.999Z",
                      a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                  ip1Count++;
                }
              }
              assertEquals(1, ip1Count);
              assertEquals(1, ip2Count);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void perEndpointErrorRateTestStream2() throws Exception {
    // this test case contains: IPs that do not make enough bad requests to trigger alert,
    // ip that triggers alert with violations all in one pane, and an ip that triggers alert
    // with events between two panes. Requests are for multiple endpoints matching regex.
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate2/httpreq_perendpointerrorrate2_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate2/httpreq_perendpointerrorrate2_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate2/httpreq_perendpointerrorrate2_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "4:GET:/t.*";
    options.setPerEndpointErrorRatePaths(v);
    options.setPerEndpointErrorRateAnalysisSuppressRecovery(60);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(15)))
            .advanceProcessingTime(Duration.standardSeconds(15))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(45)))
            .advanceProcessingTime(Duration.standardSeconds(30))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(1L, 1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              int ip1Count = 0;
              int ip2Count = 0;
              for (Alert a : i) {
                if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS).equals("192.168.1.2")) {
                  assertEquals("1970-01-01T00:00:00.000Z", a.getTimestamp().toString());
                  assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals(
                      "test httprequest per_endpoint_error_rate 192.168.1.2 GET /t.* 5",
                      a.getSummary());
                  assertEquals("test per_endpoint_error_rate", a.getNotifyMergeKey());
                  assertEquals(
                      "per_endpoint_error_rate",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                  assertEquals(5L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                  assertEquals(
                      "1970-01-01T00:00:59.999Z",
                      a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                  ip2Count++;
                } else if (a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS).equals("192.168.1.1")) {
                  assertEquals("1970-01-01T00:00:45.000Z", a.getTimestamp().toString());
                  assertEquals("192.168.1.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals(
                      "test httprequest per_endpoint_error_rate 192.168.1.1 GET /t.* 5",
                      a.getSummary());
                  assertEquals("test per_endpoint_error_rate", a.getNotifyMergeKey());
                  assertEquals(
                      "per_endpoint_error_rate",
                      a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                  assertEquals(5L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                  assertEquals(
                      "1970-01-01T00:01:44.999Z",
                      a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                  ip1Count++;
                }
              }
              assertEquals(1, ip1Count);
              assertEquals(1, ip2Count);

              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void perEndpointErrorRateTestStream3() throws Exception {
    // this test case contains: IPs that do not make enough bad requests to trigger alert,
    // ip that triggers alert with violations all in one pane, and an ip that does not trigger
    // an alert as it makes bad requests split into two sessions. Requests match one endpoint.
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate3/httpreq_perendpointerrorrate3_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate3/httpreq_perendpointerrorrate3_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate3/httpreq_perendpointerrorrate3_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "4:GET:/test";
    options.setPerEndpointErrorRatePaths(v);
    options.setPerEndpointErrorRateAnalysisSuppressRecovery(60);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(15)))
            .advanceProcessingTime(Duration.standardSeconds(15))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(75)))
            .advanceProcessingTime(Duration.standardSeconds(60))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(0L);

    p.run().waitUntilFinish();
  }

  @Test
  public void perEndpointErrorRateTestStream4() throws Exception {
    // this test case is meant to simulate guessing ids in urls.
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate4/httpreq_perendpointerrorrate4_1.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "4:GET:/test/(\\d+)/profile";
    options.setPerEndpointErrorRatePaths(v);
    options.setPerEndpointErrorRateAnalysisSuppressRecovery(60);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("1970-01-01T00:00:00.000Z", a.getTimestamp().toString());
                assertEquals("192.168.1.3", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest per_endpoint_error_rate 192.168.1.3 GET /test/(\\d+)/profile 6",
                    a.getSummary());
                assertEquals("test per_endpoint_error_rate", a.getNotifyMergeKey());
                assertEquals(
                    "per_endpoint_error_rate",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                assertEquals(6L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                assertEquals(
                    "1970-01-01T00:00:59.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void perEndpointErrorRateTestStream5() throws Exception {
    // this test case simulates an ip that makes a few requests that generate errors
    // then makes only "good" requests for a duration longer than the session
    // gap duration and then makes an request generating an error.
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate5/httpreq_perendpointerrorrate5_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate5/httpreq_perendpointerrorrate5_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate5/httpreq_perendpointerrorrate5_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "4:GET:/test";
    options.setPerEndpointErrorRatePaths(v);
    options.setPerEndpointErrorRateAnalysisSuppressRecovery(60);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(45)))
            .advanceProcessingTime(Duration.standardSeconds(45))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(70)))
            .advanceProcessingTime(Duration.standardSeconds(25))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(0L);

    p.run().waitUntilFinish();
  }

  @Test
  public void perEndpointErrorRateTestStream6() throws Exception {
    // this test case checks only the alert with maximum violations
    // is output and it is suppressed in subsequent firings until
    // the number of violations increases
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate6/httpreq_perendpointerrorrate6_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate6/httpreq_perendpointerrorrate6_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_perendpointerrorrate6/httpreq_perendpointerrorrate6_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[2];
    v[0] = "4:GET:/test";
    v[1] = "4:GET:/t.*";
    options.setPerEndpointErrorRatePaths(v);
    options.setPerEndpointErrorRateAnalysisSuppressRecovery(60);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(15)))
            .advanceProcessingTime(Duration.standardSeconds(15))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(45)))
            .advanceProcessingTime(Duration.standardSeconds(30))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(1L, 1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              int resultCount1 = 0;
              int resultCount2 = 0;
              for (Alert a : i) {
                // applies to every alert
                assertEquals("test per_endpoint_error_rate", a.getNotifyMergeKey());
                assertEquals(
                    "per_endpoint_error_rate",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                switch (a.getSummary()) {
                  case ("test httprequest per_endpoint_error_rate 192.168.1.2 GET /t.* 7"):
                    assertEquals("1970-01-01T00:00:00.000Z", a.getTimestamp().toString());
                    assertEquals(7L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                    assertEquals(
                        "1970-01-01T00:00:59.999Z",
                        a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                    assertEquals("/t.*", a.getMetadataValue(AlertMeta.Key.ENDPOINT_PATTERN));
                    resultCount1++;
                    break;
                  case ("test httprequest per_endpoint_error_rate 192.168.1.2 GET /t.* 18"):
                    assertEquals("1970-01-01T00:00:45.000Z", a.getTimestamp().toString());
                    assertEquals(18L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                    assertEquals(
                        "1970-01-01T00:01:44.999Z",
                        a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                    assertEquals("/t.*", a.getMetadataValue(AlertMeta.Key.ENDPOINT_PATTERN));
                    resultCount2++;
                    break;
                  default:
                    fail(String.format("Unknown alert summary %s", a.getSummary()));
                }
              }
              assertEquals(1, resultCount1);
              assertEquals(1, resultCount2);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
