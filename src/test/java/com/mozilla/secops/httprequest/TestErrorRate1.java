package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestErrorRate1 {
  public TestErrorRate1() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setMonitoredResourceIndicator("test");
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setGenerateConfigurationTicksInterval(1);
    ret.setGenerateConfigurationTicksMaximum(5L);
    return ret;
  }

  public void runAssertions(PCollection<Alert> results) {
    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .isEqualTo(6L); // Should have one alert and 5 configuration events

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                if (a.getMetadataValue(AlertMeta.Key.CATEGORY).equals("error_rate")) {
                  assertEquals("10.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("test httprequest error_rate 10.0.0.1 35", a.getSummary());
                  assertEquals("error_rate", a.getMetadataValue(AlertMeta.Key.CATEGORY));
                  assertEquals(
                      35L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_COUNT), 10));
                  assertEquals(
                      30L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_THRESHOLD), 10));
                  assertEquals(
                      "1970-01-01T00:00:59.999Z",
                      a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                } else if (a.getMetadataValue(AlertMeta.Key.CATEGORY).equals("cfgtick")) {
                  assertEquals("httprequest-cfgtick", a.getCategory());
                  assertEquals("test", a.getCustomMetadataValue("monitoredResourceIndicator"));
                  if (a.getCustomMetadataValue("inputFile") != null) {
                    // In the case where pipeline options are used to control input, we will have an
                    // entry corresponding to the input in the cfgtick
                    assertEquals(
                        "./target/test-classes/testdata/httpreq_errorrate1.txt",
                        a.getCustomMetadataValue("inputFile"));
                  }
                  assertEquals("true", a.getCustomMetadataValue("useEventTimestamp"));
                  assertEquals("5", a.getCustomMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alert if a single source address generates more than 30 4xx errors "
                          + "in a 1 minute window.",
                      a.getCustomMetadataValue("heuristic_ErrorRateAnalysis"));
                } else {
                  fail("unexpected category");
                }
              }
              return null;
            });
  }

  @Test
  public void errorRateTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    // Enable configuration tick generation in the pipeline for this test, and use Input
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_errorrate1.txt"});
    options.setEnableErrorRateAnalysis(true);
    options.setMaxClientErrorRate(30L);
    options.setIgnoreInternalRequests(false); // Tests use internal subnets
    // Also set a fast matcher configuration and other filters to verify the cfgtick events are
    // passed
    options.setParserFastMatcher("prod-send");
    options.setStackdriverProjectFilter("test");

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    runAssertions(results);

    p.run().waitUntilFinish();
  }

  @Test
  public void errorRateTestCfg() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setPipelineMultimodeConfiguration("/testdata/httpreq_errorrate1_single.json");

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    runAssertions(results);

    p.run().waitUntilFinish();
  }
}
