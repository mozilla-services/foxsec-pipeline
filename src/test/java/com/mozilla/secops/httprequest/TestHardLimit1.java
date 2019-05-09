package com.mozilla.secops.httprequest;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

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

public class TestHardLimit1 {
  public TestHardLimit1() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setHardLimitRequestCount(10L);
    ret.setMonitoredResourceIndicator("test");
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void hardLimitTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_hardlimit1.txt", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    PCollection<Alert> results =
        input
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.WindowForFixed())
            .apply(new HTTPRequest.HardLimitAnalysis(options));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .isEqualTo(2L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertThat(
                    a.getMetadataValue("sourceaddress"),
                    anyOf(equalTo("192.168.1.2"), equalTo("192.168.1.4")));
                String summary =
                    String.format(
                        "test httprequest hard_limit %s 11", a.getMetadataValue("sourceaddress"));
                assertEquals(summary, a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue("count")));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("request_threshold")));
                assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void hardLimitTestWithNatDetect() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_hardlimit1.txt", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    PCollection<Event> events =
        input.apply(new HTTPRequest.Parse(options)).apply(new HTTPRequest.WindowForFixed());

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Alert> results = events.apply(new HTTPRequest.HardLimitAnalysis(options, natView));

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
                assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                assertEquals("test httprequest hard_limit 192.168.1.2 11", a.getSummary());
                assertEquals(11L, Long.parseLong(a.getMetadataValue("count")));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("request_threshold")));
                assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
