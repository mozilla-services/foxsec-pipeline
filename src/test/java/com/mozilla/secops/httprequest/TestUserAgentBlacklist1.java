package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.alert.Alert;
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
                assertEquals("192.168.1.4", a.getMetadataValue("sourceaddress"));
                String summary =
                    String.format(
                        "test httprequest useragent_blacklist %s",
                        a.getMetadataValue("sourceaddress"));
                assertEquals("useragent_blacklist", a.getMetadataValue("category"));
                assertEquals(summary, a.getSummary());
                assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
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

    p.run().waitUntilFinish();
  }
}
