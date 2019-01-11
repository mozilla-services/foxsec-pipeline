package com.mozilla.secops.httprequest;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestProjectFilter {
  public TestProjectFilter() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void noFilterTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_projectfilter.txt", p);

    PCollection<Event> events = input.apply(new HTTPRequest.ParseAndWindow(true));
    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .containsInAnyOrder(2L);

    p.run().waitUntilFinish();
  }

  @Test
  public void withFilterTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_projectfilter.txt", p);

    HTTPRequest.ParseAndWindow pw = new HTTPRequest.ParseAndWindow(true);
    pw.withStackdriverProjectFilter("test");
    PCollection<Event> events = input.apply(pw);
    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .containsInAnyOrder(1L);

    p.run().waitUntilFinish();
  }
}
