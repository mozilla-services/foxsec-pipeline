package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestStatusCodeRateAnalysis {

  public TestStatusCodeRateAnalysis() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    ret.setMonitoredResourceIndicator("test");
    return ret;
  }

  @Test
  public void statusCodeRateTestBelowThreshold() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_statuscodeanalysis.txt"});
    options.setEnableStatusCodeRateAnalysis(true);
    options.setStatusCodeRateAnalysisCode(302);
    options.setMaxClientStatusCodeRate(3L);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());
    PAssert.thatSingleton(count).isEqualTo(0L);

    p.run().waitUntilFinish();
  }

  @Test
  public void statusCodeRateTestAboveThreshold() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    options.setInputFile(
        new String[] {"./target/test-classes/testdata/httpreq_statuscodeanalysis.txt"});
    options.setEnableStatusCodeRateAnalysis(true);
    options.setStatusCodeRateAnalysisCode(302);
    options.setMaxClientStatusCodeRate(2L);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> count = results.apply(Count.globally());
    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("192.168.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals(
                    "test httprequest status_code_rate_analysis 192.168.0.1 3", a.getSummary());
                assertEquals(3L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT)));
                assertEquals(2L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.THRESHOLD)));
                assertEquals(
                    "2021-05-08T19:15:59.999Z", a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
