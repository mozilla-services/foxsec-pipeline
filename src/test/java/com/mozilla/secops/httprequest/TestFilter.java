package com.mozilla.secops.httprequest;

import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.TupleTag;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestFilter {
  public TestFilter() {}

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
  public void noProjectFilterTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_filter.txt"});

    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .isEqualTo(3L);

    p.run().waitUntilFinish();
  }

  @Test
  public void withProjectFilterTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setStackdriverProjectFilter("test");
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_filter.txt"});

    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .isEqualTo(1L);

    p.run().waitUntilFinish();
  }

  @Test
  public void withLabelFilterTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setStackdriverLabelFilters(new String[] {"env:holodeck"});
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_filter.txt"});

    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .isEqualTo(2L);

    p.run().waitUntilFinish();
  }

  @Test
  public void withCidrFilterTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_filter.txt"});
    options.setCidrExclusionList("/testdata/cidrutil2.txt");
    HTTPRequestToggles toggles = HTTPRequestToggles.fromPipelineOptions(options);
    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequestElementFilter(toggles))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .isEqualTo(2L);

    p.run().waitUntilFinish();
  }

  @Test
  public void withNoMatchLabelFilterTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_filter.txt"});
    options.setStackdriverLabelFilters(new String[] {"env:hydroponicsbay"});

    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.that(count).inWindow(new IntervalWindow(new Instant(0L), new Instant(60000))).empty();

    p.run().waitUntilFinish();
  }

  @Test
  public void hostNoFilterTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_urlhostfilter.txt"});

    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .isEqualTo(4L);

    p.run().waitUntilFinish();
  }

  @Test
  public void hostFilterTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_urlhostfilter.txt"});
    options.setIncludeUrlHostRegex(new String[] {"wontmatch", "^send\\..*"});

    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .isEqualTo(2L);

    p.run().waitUntilFinish();
  }

  @Test
  public void hostFilterNoMatchTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_urlhostfilter.txt"});
    options.setIncludeUrlHostRegex(new String[] {"wontmatch", "wontmatch2"});

    PCollection<Event> events =
        HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options)
            .get(new TupleTag<Event>("test"))
            .apply(new HTTPRequest.WindowForFixed());

    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.that(count).inWindow(new IntervalWindow(new Instant(0L), new Instant(60000))).empty();

    p.run().waitUntilFinish();
  }
}
