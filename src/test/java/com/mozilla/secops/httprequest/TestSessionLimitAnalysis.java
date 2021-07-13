package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.IprepdIO;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestSessionLimitAnalysis {

  public TestSessionLimitAnalysis() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setMonitoredResourceIndicator("test");
    ret.setEnableSessionLimitAnalysis(true);
    ret.setSessionGapDurationMinutes(20L);
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void sessionLimitAnalysisMonitorOnly() throws Exception {
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_sessionlimitanalysis1/httpreq_sessionlimitanalysis1_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_sessionlimitanalysis1/httpreq_sessionlimitanalysis1_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_sessionlimitanalysis1/httpreq_sessionlimitanalysis1_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "6:20:POST:^/submit/click.*";
    options.setSessionLimitAnalysisPaths(v);
    options.setSessionLimitAnalysisSuppressRecovery(60);
    options.setUseXffAsRemote(true);
    options.setUseProxyXff(true);

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080|test", null);
    options.setOutputIprepd(new String[] {"http://127.0.0.1:8080|test"});

    Instant start = Instant.parse("2021-07-08T21:58:40.0157Z");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(start)
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(start.plus(Duration.standardMinutes(15)))
            .advanceProcessingTime(Duration.standardMinutes(20))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(start.plus(Duration.standardMinutes(30)))
            .advanceProcessingTime(Duration.standardMinutes(8))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    results
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(MapElements.via(new AlertFormatter.AlertToString()))
        .apply(OutputOptions.compositeOutput(options));

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("2021-07-08T22:40:42.000Z", a.getTimestamp().toString());
                assertEquals("192.168.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest session_limit_analysis_monitor_only 192.168.0.1 POST ^/submit/click.* 7",
                    a.getSummary());
                assertEquals("test session_limit_analysis_monitor_only", a.getNotifyMergeKey());
                assertEquals(
                    "session_limit_analysis_monitor_only",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                assertEquals(
                    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                    a.getMetadataValue(AlertMeta.Key.USERAGENT));
                assertEquals(7L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT)));
                assertEquals(
                    "2021-07-08T23:00:41.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                assertEquals("2021-07-08T21:59:42.000Z", a.getMetadataValue(AlertMeta.Key.START));
              }
              return null;
            });

    assertEquals(100, (int) r.getReputation("ip", "192.168.0.1"));
    p.run().waitUntilFinish();

    // monitor only, no iprepd escalation
    assertEquals(100, (int) r.getReputation("ip", "192.168.0.1"));
  }

  @Test
  public void sessionLimitAnalysisAlert() throws Exception {
    String[] eb1 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_sessionlimitanalysis1/httpreq_sessionlimitanalysis1_1.txt");
    String[] eb2 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_sessionlimitanalysis1/httpreq_sessionlimitanalysis1_2.txt");
    String[] eb3 =
        TestUtil.getTestInputArray(
            "/testdata/httpreq_sessionlimitanalysis1/httpreq_sessionlimitanalysis1_3.txt");

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "6:7:POST:^/submit/click.*";
    options.setSessionLimitAnalysisPaths(v);
    options.setSessionLimitAnalysisSuppressRecovery(60);
    options.setUseXffAsRemote(true);
    options.setUseProxyXff(true);

    IprepdIO.Reader r = IprepdIO.getReader("http://127.0.0.1:8080|test", null);
    options.setOutputIprepd(new String[] {"http://127.0.0.1:8080|test"});

    Instant start = Instant.parse("2021-07-08T21:58:40.0157Z");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(start)
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(start.plus(Duration.standardMinutes(15)))
            .advanceProcessingTime(Duration.standardMinutes(20))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(start.plus(Duration.standardMinutes(30)))
            .advanceProcessingTime(Duration.standardMinutes(8))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    // Hook the output up to the composite output transform so we get local iprepd submission
    // in the tests
    results
        .apply(ParDo.of(new AlertFormatter(options)))
        .apply(MapElements.via(new AlertFormatter.AlertToString()))
        .apply(OutputOptions.compositeOutput(options));

    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("2021-07-08T22:40:42.000Z", a.getTimestamp().toString());
                assertEquals("192.168.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest session_limit_analysis 192.168.0.1 POST ^/submit/click.* 7",
                    a.getSummary());
                assertEquals("test session_limit_analysis", a.getNotifyMergeKey());
                assertEquals(
                    "session_limit_analysis",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals("60", a.getMetadataValue(AlertMeta.Key.IPREPD_SUPPRESS_RECOVERY));
                assertEquals(
                    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                    a.getMetadataValue(AlertMeta.Key.USERAGENT));
                assertEquals(7L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT)));
                assertEquals(
                    "2021-07-08T23:00:41.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                assertEquals("2021-07-08T21:59:42.000Z", a.getMetadataValue(AlertMeta.Key.START));
              }
              return null;
            });

    assertEquals(100, (int) r.getReputation("ip", "192.168.0.1"));
    p.run().waitUntilFinish();

    // escalate to iprepd
    assertEquals(80, (int) r.getReputation("ip", "192.168.0.1"));
  }
}
