package com.mozilla.secops.httprequest;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
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

public class TestEndpointAbuse1 {
  public TestEndpointAbuse1() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setMonitoredResourceIndicator("test");
    ret.setSessionGapDurationMinutes(20L);
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void endpointAbuseTestStream() throws Exception {
    String[] eb1 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse1/httpreq_endpointabuse1_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse1/httpreq_endpointabuse1_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse1/httpreq_endpointabuse1_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "8:GET:/test";
    options.setEndpointAbusePath(v);
    options.setEndpointAbuseSuppressRecovery(60);

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

    PCollection<Alert> results =
        p.apply(s)
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.KeyAndWindowForSessionsFireEarly(options))
            .apply(new HTTPRequest.EndpointAbuseAnalysis(options));

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("1970-01-01T00:00:15.000Z", a.getTimestamp().toString());
                assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                assertEquals(
                    "test httprequest endpoint_abuse 192.168.1.2 GET /test 10", a.getSummary());
                assertEquals("endpoint_abuse", a.getNotifyMergeKey());
                assertEquals("endpoint_abuse", a.getMetadataValue("category"));
                assertEquals("60", a.getMetadataValue("iprepd_suppress_recovery"));
                assertEquals("Mozilla", a.getMetadataValue("useragent"));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("count"), 10));
                assertEquals("1970-01-01T00:20:14.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void endpointAbuseTestStreamExtendedVariance() throws Exception {
    String[] eb1 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse2/httpreq_endpointabuse2_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse2/httpreq_endpointabuse2_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse2/httpreq_endpointabuse2_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "8:GET:/test";
    options.setEndpointAbusePath(v);
    options.setEndpointAbuseExtendedVariance(true);

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
            .advanceProcessingTime(Duration.standardSeconds(60))
            .advanceWatermarkToInfinity();

    PCollection<Alert> results =
        p.apply(s)
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.KeyAndWindowForSessionsFireEarly(options))
            .apply(new HTTPRequest.EndpointAbuseAnalysis(options));

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(0L, 1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                assertEquals(
                    "test httprequest endpoint_abuse 192.168.1.2 GET /test 10", a.getSummary());
                assertEquals("endpoint_abuse", a.getNotifyMergeKey());
                assertEquals("endpoint_abuse", a.getMetadataValue("category"));
                assertEquals("Mozilla", a.getMetadataValue("useragent"));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("count"), 10));
                assertEquals("1970-01-01T00:20:14.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void endpointAbuseTestStreamCustomVariance() throws Exception {
    String[] eb1 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse5/httpreq_endpointabuse5_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse5/httpreq_endpointabuse5_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse5/httpreq_endpointabuse5_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "8:GET:/test";
    options.setEndpointAbusePath(v);
    options.setEndpointAbuseExtendedVariance(true);
    options.setEndpointAbuseCustomVarianceSubstrings(new String[] {"init?"});

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
            .advanceProcessingTime(Duration.standardSeconds(60))
            .advanceWatermarkToInfinity();

    PCollection<Alert> results =
        p.apply(s)
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.KeyAndWindowForSessionsFireEarly(options))
            .apply(new HTTPRequest.EndpointAbuseAnalysis(options));

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(0L, 1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                assertEquals(
                    "test httprequest endpoint_abuse 192.168.1.2 GET /test 10", a.getSummary());
                assertEquals("endpoint_abuse", a.getNotifyMergeKey());
                assertEquals("endpoint_abuse", a.getMetadataValue("category"));
                assertEquals("Mozilla", a.getMetadataValue("useragent"));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("count"), 10));
                assertEquals("1970-01-01T00:20:14.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void endpointAbuseTestStreamStateExpiry() throws Exception {
    String[] eb1 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse4/httpreq_endpointabuse4_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse4/httpreq_endpointabuse4_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse4/httpreq_endpointabuse4_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "8:GET:/test";
    options.setEndpointAbusePath(v);
    options.setEndpointAbuseSuppressRecovery(60);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(15)))
            .advanceProcessingTime(Duration.standardSeconds(15))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(1785)))
            .advanceProcessingTime(Duration.standardMinutes(30))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    PCollection<Alert> results =
        p.apply(s)
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.KeyAndWindowForSessionsFireEarly(options))
            .apply(new HTTPRequest.EndpointAbuseAnalysis(options));

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(1L, 1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertThat(
                    a.getTimestamp().toString(),
                    anyOf(
                        equalTo("1970-01-01T00:00:00.000Z"), equalTo("1970-01-01T00:30:00.000Z")));
                assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                assertEquals(
                    "test httprequest endpoint_abuse 192.168.1.2 GET /test 10", a.getSummary());
                assertEquals("endpoint_abuse", a.getNotifyMergeKey());
                assertEquals("endpoint_abuse", a.getMetadataValue("category"));
                assertEquals("60", a.getMetadataValue("iprepd_suppress_recovery"));
                assertEquals("Mozilla", a.getMetadataValue("useragent"));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("count"), 10));
                assertThat(
                    a.getMetadataValue("window_timestamp"),
                    anyOf(
                        equalTo("1970-01-01T00:19:59.999Z"), equalTo("1970-01-01T00:49:59.999Z")));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void endpointAbuseTestPreprocessFilter() throws Exception {
    String[] eb1 =
        TestUtil.getTestInputArray("/testdata/httpreq_endpointabuse3/httpreq_endpointabuse3_1.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[2];
    v[0] = "8:GET:/test";
    v[1] = "8:GET:/test2";
    options.setEndpointAbusePath(v);
    String w[] = new String[2];
    w[0] = "GET:/test";
    w[1] = "GET:/test2";
    options.setFilterRequestPath(w);

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    PCollection<Alert> results =
        p.apply(s)
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.KeyAndWindowForSessionsFireEarly(options))
            .apply(new HTTPRequest.EndpointAbuseAnalysis(options));

    PCollection<Long> count = results.apply(Count.globally());
    PAssert.that(count).containsInAnyOrder(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("192.168.1.6", a.getMetadataValue("sourceaddress"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
