package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.httprequest.HTTPRequest.ThresholdAnalysis;
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

public class TestThresholdAnalysis1 {
  public TestThresholdAnalysis1() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setAnalysisThresholdModifier(1.0);
    ret.setEnableThresholdAnalysis(true);
    ret.setMonitoredResourceIndicator("test");
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    ret.setRequiredMinimumRequestsPerClient(2L);
    ret.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_thresholdanalysis1.txt"});
    return ret;
  }

  @Test
  public void thresholdAnalysisTest() throws Exception {
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
                assertEquals("10.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals("test httprequest threshold_analysis 10.0.0.1 100", a.getSummary());
                assertEquals(100L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                assertEquals(
                    10.90, Double.parseDouble(a.getMetadataValue(AlertMeta.Key.MEAN)), 0.1);
                assertEquals(
                    1.0,
                    Double.parseDouble(a.getMetadataValue(AlertMeta.Key.THRESHOLD_MODIFIER)),
                    0.1);
                assertEquals(
                    "1970-01-01T00:00:59.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestWithNatDetect() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_thresholdanalysisnatdetect1.txt"});
    options.setNatDetection(true);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    // 10.0.0.2 would normally trigger a result being emitted, but with NAT detection enabled
    // we should only see a single result for 10.0.0.1 in the selected interval window
    PAssert.thatSingleton(resultCount).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("10.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(100L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT), 10));
                assertEquals(
                    18.33, Double.parseDouble(a.getMetadataValue(AlertMeta.Key.MEAN)), 0.1);
                assertEquals(
                    1.0,
                    Double.parseDouble(a.getMetadataValue(AlertMeta.Key.THRESHOLD_MODIFIER)),
                    0.1);
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
                            ThresholdAnalysis.class.getName(),
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
  public void thresholdAnalysisTestRequiredMinimum() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    // Set a minimum average well above what we will calculate with the test data set
    options.setRequiredMinimumAverage(250.0);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_thresholdanalysisnatdetect1.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    // No results should have been emitted
    PAssert.that(resultCount).empty();

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestRequiredMinimumClients() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    // Set a required minimum above what we have in the test data set
    options.setRequiredMinimumClients(500L);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_thresholdanalysisnatdetect1.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    // No results should have been emitted
    PAssert.that(resultCount).empty();

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestClampMaximum() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setClampThresholdMaximum(1.0);
    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_thresholdanalysisnatdetect1.txt"});

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount).isEqualTo(12L);

    p.run().waitUntilFinish();
  }
}
