package com.mozilla.secops.httprequest;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

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
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    return ret;
  }

  @Test
  public void countRequestsTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_errorrate1.txt.gz", p);

    PCollection<Event> events =
        input
            .apply(new HTTPRequest.Parse(getTestOptions()))
            .apply(new HTTPRequest.WindowForFixed());
    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .containsInAnyOrder(720L);
    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000)))
        .containsInAnyOrder(720L);

    p.run().waitUntilFinish();
  }

  @Test
  public void errorRateTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_errorrate1.txt.gz", p);

    PCollection<Alert> results =
        input
            .apply(new HTTPRequest.Parse(getTestOptions()))
            .apply(new HTTPRequest.WindowForFixed())
            .apply(new HTTPRequest.ErrorRateAnalysis(30L));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.that(resultCount)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .containsInAnyOrder(2L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertThat(
                    a.getMetadataValue("sourceaddress"),
                    anyOf(equalTo("10.0.0.1"), equalTo("10.0.0.2")));
                assertEquals(a.getMetadataValue("category"), "error_rate");
                assertEquals(60L, Long.parseLong(a.getMetadataValue("error_count"), 10));
                assertEquals(30L, Long.parseLong(a.getMetadataValue("error_threshold"), 10));
                assertEquals("1970-01-01T00:05:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
