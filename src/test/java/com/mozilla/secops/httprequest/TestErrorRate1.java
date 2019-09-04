package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.alert.Alert;
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
    ret.setMaxClientErrorRate(30L);
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void errorRateTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    // Enable configuration tick generation in the pipeline for this test, and use Input
    options.setGenerateConfigurationTicksInterval(1);
    options.setGenerateConfigurationTicksMaximum(5L);
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_errorrate1.txt"});
    options.setEnableErrorRateAnalysis(true);
    // Also set a fast matcher configuration and other filters to verify the cfgtick events are
    // passed
    options.setParserFastMatcher("prod-send");
    options.setStackdriverProjectFilter("test");

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
            p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options);

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .isEqualTo(6L); // Should have one alert and 5 configuration events

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                if (a.getMetadataValue("category").equals("error_rate")) {
                  assertEquals("10.0.0.1", a.getMetadataValue("sourceaddress"));
                  assertEquals("test httprequest error_rate 10.0.0.1 35", a.getSummary());
                  assertEquals("error_rate", a.getMetadataValue("category"));
                  assertEquals(35L, Long.parseLong(a.getMetadataValue("error_count"), 10));
                  assertEquals(30L, Long.parseLong(a.getMetadataValue("error_threshold"), 10));
                  assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
                } else if (a.getMetadataValue("category").equals("cfgtick")) {
                  assertEquals("httprequest-cfgtick", a.getCategory());
                  assertEquals("test", a.getMetadataValue("monitoredResourceIndicator"));
                  assertEquals(
                      "./target/test-classes/testdata/httpreq_errorrate1.txt",
                      a.getMetadataValue("inputFile"));
                  assertEquals("true", a.getMetadataValue("useEventTimestamp"));
                  assertEquals("5", a.getMetadataValue("generateConfigurationTicksMaximum"));
                  assertEquals(
                      "Alert if a single source address generates more than 30 4xx errors "
                          + "in a 1 minute window.",
                      a.getMetadataValue("heuristic_ErrorRateAnalysis"));
                } else {
                  fail("unexpected category");
                }
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
