package com.mozilla.secops.httprequest;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestThresholdAnalysis1 {
  public TestThresholdAnalysis1() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setAnalysisThresholdModifier(1.0);
    return ret;
  }

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

  @Test
  public void countRequestsTest() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/httpreq_thresholdanalysis1.txt.gz", p);

    PCollection<Event> events =
        input
            .apply(new HTTPRequest.Parse(getTestOptions()))
            .apply(new HTTPRequest.WindowForFixed());
    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .containsInAnyOrder(2400L);
    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000)))
        .containsInAnyOrder(2520L);

    p.run().waitUntilFinish();
  }

  @Test
  public void countInWindowTest() throws Exception {
    ArrayList<KV<String, Long>> expect =
        new ArrayList<KV<String, Long>>(
            Arrays.asList(
                KV.of("192.168.1.1", 60L),
                KV.of("192.168.1.2", 60L),
                KV.of("192.168.1.3", 60L),
                KV.of("192.168.1.4", 60L),
                KV.of("192.168.1.5", 60L),
                KV.of("192.168.1.6", 60L),
                KV.of("192.168.1.7", 60L),
                KV.of("192.168.1.8", 60L),
                KV.of("192.168.1.9", 60L),
                KV.of("192.168.1.10", 60L),
                KV.of("10.0.0.1", 900L),
                KV.of("10.0.0.2", 900L)));
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/httpreq_thresholdanalysis1.txt.gz", p);

    PCollection<KV<String, Long>> counts =
        input
            .apply(new HTTPRequest.Parse(getTestOptions()))
            .apply(new HTTPRequest.WindowForFixed())
            .apply(new HTTPRequest.CountInWindow());

    PAssert.that(counts)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .containsInAnyOrder(expect);

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTest() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/httpreq_thresholdanalysis1.txt.gz", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    PCollection<Alert> results =
        input
            .apply(new HTTPRequest.Parse(options))
            .apply(new HTTPRequest.WindowForFixed())
            .apply(new HTTPRequest.CountInWindow())
            .apply(new HTTPRequest.ThresholdAnalysis(options));

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
                assertEquals(900L, Long.parseLong(a.getMetadataValue("count"), 10));
                assertEquals(180.0, Double.parseDouble(a.getMetadataValue("mean")), 0.1);
                assertEquals(
                    1.0, Double.parseDouble(a.getMetadataValue("threshold_modifier")), 0.1);
                assertEquals("1970-01-01T00:05:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestWithNatDetect() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/httpreq_thresholdanalysisnatdetect1.txt.gz", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    PCollection<Event> events =
        input.apply(new HTTPRequest.Parse(options)).apply(new HTTPRequest.WindowForFixed());

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Alert> results =
        events
            .apply(new HTTPRequest.CountInWindow())
            .apply(new HTTPRequest.ThresholdAnalysis(options, natView));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    // 10.0.0.2 would normally trigger a result being emitted, but with NAT detection enabled
    // we should only see a single result for 10.0.0.1 in the selected interval window
    PAssert.that(resultCount)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .containsInAnyOrder(1L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .satisfies(
            i -> {
              for (Alert a : i) {
                assertEquals("10.0.0.1", a.getMetadataValue("sourceaddress"));
                assertEquals(900L, Long.parseLong(a.getMetadataValue("count"), 10));
                assertEquals(180.0, Double.parseDouble(a.getMetadataValue("mean")), 0.1);
                assertEquals(
                    1.0, Double.parseDouble(a.getMetadataValue("threshold_modifier")), 0.1);
                assertEquals("1970-01-01T00:05:59.999Z", a.getMetadataValue("window_timestamp"));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestRequiredMinimum() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/httpreq_thresholdanalysisnatdetect1.txt.gz", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    // Set a minimum average well above what we will calculate with the test data set
    options.setRequiredMinimumAverage(250.0);

    PCollection<Event> events =
        input.apply(new HTTPRequest.Parse(options)).apply(new HTTPRequest.WindowForFixed());

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Alert> results =
        events
            .apply(new HTTPRequest.CountInWindow())
            .apply(new HTTPRequest.ThresholdAnalysis(options, natView));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    // No results should have been emitted
    PAssert.that(resultCount).empty();

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestRequiredMinimumClients() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/httpreq_thresholdanalysisnatdetect1.txt.gz", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    // Set a required minimum above what we have in the test data set
    options.setRequiredMinimumClients(500L);

    PCollection<Event> events =
        input.apply(new HTTPRequest.Parse(options)).apply(new HTTPRequest.WindowForFixed());

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Alert> results =
        events
            .apply(new HTTPRequest.CountInWindow())
            .apply(new HTTPRequest.ThresholdAnalysis(options, natView));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    // No results should have been emitted
    PAssert.that(resultCount).empty();

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestClampMaximum() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/httpreq_thresholdanalysisnatdetect1.txt.gz", p);

    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setClampThresholdMaximum(1.0);

    PCollection<Event> events =
        input.apply(new HTTPRequest.Parse(options)).apply(new HTTPRequest.WindowForFixed());

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Alert> results =
        events
            .apply(new HTTPRequest.CountInWindow())
            .apply(new HTTPRequest.ThresholdAnalysis(options));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.that(resultCount)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .containsInAnyOrder(14L);

    p.run().waitUntilFinish();
  }
}
