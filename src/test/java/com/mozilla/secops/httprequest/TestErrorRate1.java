package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.window.GlobalTriggers;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
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
    ret.setMonitoredResourceIndicator("test");
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setMaxClientErrorRate(30L);
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    return ret;
  }

  @Test
  public void countRequestsTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/httpreq_errorrate1.txt", p);

    PCollection<Event> events =
        input
            .apply(new HTTPRequest.Parse(getTestOptions()))
            .apply(new HTTPRequest.WindowForFixed());
    PCollection<Long> count =
        events.apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count)
        .inOnlyPane(new IntervalWindow(new Instant(0L), new Instant(60000L)))
        .isEqualTo(55L);

    p.run().waitUntilFinish();
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
    PCollection<Event> events =
        p.apply(Input.compositeInputAdapter(options, HTTPRequest.buildConfigurationTick(options)))
            .apply(new HTTPRequest.Parse(options));

    PCollectionList<Alert> alertList = PCollectionList.empty(p);
    alertList =
        alertList.and(
            events
                .apply(new HTTPRequest.WindowForFixed())
                .apply(new HTTPRequest.ErrorRateAnalysis(options))
                .apply("error rate global triggers", new GlobalTriggers<Alert>(1)));
    alertList =
        alertList.and(
            events
                .apply(ParDo.of(new CfgTickProcessor("httprequest-cfgtick", "category")))
                .apply("cfgtick global triggers", new GlobalTriggers<Alert>(1)));
    PCollection<Alert> results = alertList.apply(Flatten.<Alert>pCollections());

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
