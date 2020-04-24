package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.HTTPRequest.UserAgentBlacklistAnalysis;
import org.apache.beam.sdk.PipelineResult;
import org.apache.beam.sdk.metrics.MetricNameFilter;
import org.apache.beam.sdk.metrics.MetricResult;
import org.apache.beam.sdk.metrics.MetricsFilter;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestUserAgentBlacklist1 {
  public TestUserAgentBlacklist1() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setUserAgentBlacklistPath("/testdata/uablacklist1.txt");
    ret.setMonitoredResourceIndicator("test");
    // Just reuse the hardlimit data set here
    ret.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_hardlimit1.txt"});
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    ret.setEnableUserAgentBlacklistAnalysis(true);
    return ret;
  }

  @Test
  public void userAgentBlacklistTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();

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
                assertEquals("192.168.1.4", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                String summary =
                    String.format(
                        "test httprequest useragent_blacklist %s",
                        a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "useragent_blacklist",
                    a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                assertEquals(summary, a.getSummary());
                assertEquals(
                    "1970-01-01T00:00:59.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void userAgentBlacklistTestWithNatDetect() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setNatDetection(true);

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
                            UserAgentBlacklistAnalysis.class.getName(),
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
}
