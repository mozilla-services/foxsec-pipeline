package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import java.util.Map;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.Instant;
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
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void userAgentBlacklistTest() throws Exception {
    // Just reuse the hardlimit data set here
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_hardlimit1.txt", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    PCollection<Alert> results =
        input
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.WindowForFixed())
            .apply(new HTTPRequest.UserAgentBlacklistAnalysis(options));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .isEqualTo(1L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000L)))
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
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_hardlimit1.txt", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    PCollection<Event> events =
        input.apply(new HTTPRequest.Parse(options)).apply(new HTTPRequest.WindowForFixed());

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Alert> results =
        events.apply(new HTTPRequest.UserAgentBlacklistAnalysis(options, natView));

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .empty();

    p.run().waitUntilFinish();
  }
}
