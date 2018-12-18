package com.mozilla.secops.httprequest;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import com.mozilla.secops.DetectNat;
import com.mozilla.secops.parser.Event;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Scanner;
import java.util.zip.GZIPInputStream;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestThresholdAnalysis1 {
  public TestThresholdAnalysis1() {}

  private PCollection<String> getInput() throws IOException {
    ArrayList<String> inputData = new ArrayList<String>();
    GZIPInputStream in =
        new GZIPInputStream(
            getClass().getResourceAsStream("/testdata/httpreq_thresholdanalysis1.txt.gz"));
    Scanner scanner = new Scanner(in);
    while (scanner.hasNextLine()) {
      inputData.add(scanner.nextLine());
    }
    scanner.close();
    return p.apply(Create.of(inputData));
  }

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

  @Test
  public void countRequestsTest() throws Exception {
    PCollection<String> input = getInput();

    PCollection<Event> events = input.apply(new HTTPRequest.ParseAndWindow(true));
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
    PCollection<String> input = getInput();

    PCollection<KV<String, Long>> counts =
        input.apply(new HTTPRequest.ParseAndWindow(true)).apply(new HTTPRequest.CountInWindow());

    PAssert.that(counts)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
        .containsInAnyOrder(expect);

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTest() throws Exception {
    PCollection<String> input = getInput();

    PCollection<Result> results =
        input
            .apply(new HTTPRequest.ParseAndWindow(true))
            .apply(new HTTPRequest.CountInWindow())
            .apply(new HTTPRequest.ThresholdAnalysis(1.0));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Result>combineFn()).withoutDefaults());
    PAssert.that(resultCount)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .containsInAnyOrder(2L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .satisfies(
            i -> {
              for (Result r : i) {
                assertThat(r.getSourceAddress(), anyOf(equalTo("10.0.0.1"), equalTo("10.0.0.2")));
                assertEquals(900L, (long) r.getCount());
                assertEquals(180.0, (double) r.getMeanValue(), 0.1);
                assertEquals(1.0, (double) r.getThresholdModifier(), 0.1);
                assertEquals(359999L, r.getWindowTimestamp().getMillis());
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void thresholdAnalysisTestWithNatDetect() throws Exception {
    PCollection<String> input = getInput();

    PCollection<Event> events = input.apply(new HTTPRequest.ParseAndWindow(true));

    PCollectionView<Map<String, Boolean>> natView = DetectNat.getView(events);

    PCollection<Result> results =
        events
            .apply(new HTTPRequest.CountInWindow())
            .apply(new HTTPRequest.ThresholdAnalysis(1.0, natView));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Result>combineFn()).withoutDefaults());
    PAssert.that(resultCount)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .containsInAnyOrder(2L);

    PAssert.that(results)
        .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000L)))
        .satisfies(
            i -> {
              for (Result r : i) {
                assertThat(r.getSourceAddress(), anyOf(equalTo("10.0.0.1"), equalTo("10.0.0.2")));
                assertEquals(900L, (long) r.getCount());
                assertEquals(180.0, (double) r.getMeanValue(), 0.1);
                assertEquals(1.0, (double) r.getThresholdModifier(), 0.1);
                assertEquals(359999L, r.getWindowTimestamp().getMillis());
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
