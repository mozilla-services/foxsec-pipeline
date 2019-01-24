package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.PCollection;
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
    return ret;
  }

  @Test
  public void endpointAbuseTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_endpointabuse1.txt", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "8:GET:/test";
    options.setEndpointAbusePath(v);

    PCollection<Alert> results =
        input
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.WindowForFixedFireEarly())
            .apply(new HTTPRequest.EndpointAbuseAnalysis(options));

    PCollection<Long> count =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());

    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(600000)))
        .containsInAnyOrder(1L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(600000)))
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                assertEquals(
                    "test httprequest endpoint_abuse 192.168.1.2 GET /test 10", a.getSummary());
                assertEquals("endpoint_abuse-192.168.1.2", a.getNotifyMergeKey());
                assertEquals("endpoint_abuse", a.getMetadataValue("category"));
                assertEquals("Mozilla", a.getMetadataValue("useragent"));
                assertEquals(10L, Long.parseLong(a.getMetadataValue("count"), 10));
                assertEquals("1970-01-01T00:09:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void endpointAbuseTestPreprocessFilter() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_endpointabuse1.txt", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    String v[] = new String[1];
    v[0] = "8:GET:/test";
    options.setEndpointAbusePath(v);
    String w[] = new String[1];
    w[0] = "GET:/test";
    options.setFilterRequestPath(w);

    PCollection<Event> events =
        input
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.WindowForFixedFireEarly());

    PCollection<Alert> results = events.apply(new HTTPRequest.EndpointAbuseAnalysis(options));

    PCollection<Long> count =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());

    PAssert.that(count).inWindow(new IntervalWindow(new Instant(0L), new Instant(600000))).empty();

    p.run().waitUntilFinish();
  }
}
