package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import java.io.Serializable;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestMulti implements Serializable {
  private static final long serialVersionUID = 1L;

  public TestMulti() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setGenerateConfigurationTicksInterval(1);
    ret.setGenerateConfigurationTicksMaximum(5L);
    return ret;
  }

  @Test
  public void testMulti1() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setPipelineMultimodeConfiguration("/testdata/httpreq_multi1.json");

    // Run the analysis; at the end plug the alert formatter in so we can validate the monitored
    // resource metadata is set correct for the common output transforms
    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
                p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options)
            .apply(ParDo.of(new AlertFormatter(options)));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .isEqualTo(12L); // Should have two alerts and 10 configuration events

    PAssert.that(results)
        .satisfies(
            i -> {
              int hlAlerts = 0;
              int erAlerts = 0;

              int r1Ticks = 0;
              int r2Ticks = 0;
              for (Alert a : i) {
                if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("hard_limit")) {
                  assertEquals("192.168.1.2", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("resource2 httprequest hard_limit 192.168.1.2 11", a.getSummary());
                  assertEquals(11L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.COUNT)));
                  assertEquals(
                      10L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.REQUEST_THRESHOLD)));
                  assertEquals(
                      "1970-01-01T00:00:59.999Z",
                      a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                  assertEquals("resource2", a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE));
                  assertEquals(
                      "resource2 hard_limit_count", a.getMetadataValue(AlertMeta.Key.NOTIFY_MERGE));
                  hlAlerts++;
                } else if (a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD)
                    .equals("error_rate")) {
                  assertEquals("10.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("resource1 httprequest error_rate 10.0.0.1 35", a.getSummary());
                  assertEquals(
                      "error_rate", a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                  assertEquals(
                      35L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_COUNT), 10));
                  assertEquals(
                      30L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_THRESHOLD), 10));
                  assertEquals(
                      "1970-01-01T00:00:59.999Z",
                      a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                  assertEquals("resource1", a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE));
                  assertEquals(
                      "resource1 error_count", a.getMetadataValue(AlertMeta.Key.NOTIFY_MERGE));
                  erAlerts++;
                } else if (a.getCategory().equals("httprequest-cfgtick")) {
                  if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE).equals("resource1")) {
                    assertNotNull(a.getCustomMetadataValue("heuristic_ErrorRateAnalysis"));
                    assertNull(a.getCustomMetadataValue("heuristic_HardLimitAnalysis"));
                    r1Ticks++;
                  } else if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE)
                      .equals("resource2")) {
                    assertNull(a.getCustomMetadataValue("heuristic_ErrorRateAnalysis"));
                    assertNotNull(a.getCustomMetadataValue("heuristic_HardLimitAnalysis"));
                    r2Ticks++;
                  } else {
                    fail("bad resource value for configuration tick");
                  }
                }
              }
              assertEquals(1, hlAlerts);
              assertEquals(1, erAlerts);

              assertEquals(5, r1Ticks);
              assertEquals(5, r2Ticks);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void testMulti2() throws Exception {
    // Tests multi configuration when we have monitored resources without any matching events
    HTTPRequest.HTTPRequestOptions options = getTestOptions();
    options.setPipelineMultimodeConfiguration("/testdata/httpreq_multi2.json");

    // Run the analysis; at the end plug the alert formatter in so we can validate the monitored
    // resource metadata is set correct for the common output transforms
    PCollection<Alert> results =
        HTTPRequest.expandInputMap(
                p, HTTPRequest.readInput(p, HTTPRequest.getInput(p, options), options), options)
            .apply(ParDo.of(new AlertFormatter(options)));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .isEqualTo(17L); // Should have two alerts and 15 configuration events

    PAssert.that(results)
        .satisfies(
            i -> {
              int r1Alerts = 0;
              int r2Alerts = 0;
              int r3Alerts = 0;

              int r1Ticks = 0;
              int r2Ticks = 0;
              int r3Ticks = 0;
              for (Alert a : i) {
                if (a.getCategory().equals("httprequest-cfgtick")) {
                  if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE).equals("resource1")) {
                    assertNotNull(a.getCustomMetadataValue("heuristic_ErrorRateAnalysis"));
                    assertNotNull(a.getCustomMetadataValue("heuristic_ThresholdAnalysis"));
                    assertNull(a.getCustomMetadataValue("heuristic_HardLimitAnalysis"));
                    r1Ticks++;
                  } else if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE)
                      .equals("resource2")) {
                    assertNotNull(a.getCustomMetadataValue("heuristic_ErrorRateAnalysis"));
                    assertNotNull(a.getCustomMetadataValue("heuristic_ThresholdAnalysis"));
                    assertNull(a.getCustomMetadataValue("heuristic_HardLimitAnalysis"));
                    r2Ticks++;
                  } else if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE)
                      .equals("resource3")) {
                    assertNotNull(a.getCustomMetadataValue("heuristic_ErrorRateAnalysis"));
                    assertNotNull(a.getCustomMetadataValue("heuristic_ThresholdAnalysis"));
                    assertNull(a.getCustomMetadataValue("heuristic_HardLimitAnalysis"));
                    r3Ticks++;
                  } else {
                    fail("bad resource value for configuration tick");
                  }
                } else {
                  if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE).equals("resource1")) {
                    assertEquals("10.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    assertEquals("resource1 httprequest error_rate 10.0.0.1 35", a.getSummary());
                    assertEquals(
                        "error_rate", a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                    assertEquals(
                        35L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_COUNT), 10));
                    assertEquals(
                        30L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_THRESHOLD), 10));
                    assertEquals(
                        "1970-01-01T00:00:59.999Z",
                        a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                    assertEquals("resource1", a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE));
                    assertEquals(
                        "resource1 error_count", a.getMetadataValue(AlertMeta.Key.NOTIFY_MERGE));
                    r1Alerts++;
                  } else if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE)
                      .equals("resource2")) {
                    r2Alerts++;
                  } else if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE)
                      .equals("resource3")) {
                    assertEquals("10.0.0.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    assertEquals("resource3 httprequest error_rate 10.0.0.1 35", a.getSummary());
                    assertEquals(
                        "error_rate", a.getMetadataValue(AlertMeta.Key.ALERT_SUBCATEGORY_FIELD));
                    assertEquals(
                        35L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_COUNT), 10));
                    assertEquals(
                        30L, Long.parseLong(a.getMetadataValue(AlertMeta.Key.ERROR_THRESHOLD), 10));
                    assertEquals(
                        "1970-01-01T00:00:59.999Z",
                        a.getMetadataValue(AlertMeta.Key.WINDOW_TIMESTAMP));
                    assertEquals("resource3", a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE));
                    assertEquals(
                        "resource3 error_count", a.getMetadataValue(AlertMeta.Key.NOTIFY_MERGE));
                    r3Alerts++;
                  } else {
                    fail("bad resource value for alert");
                  }
                }
              }

              assertEquals(1, r1Alerts);
              assertEquals(0, r2Alerts);
              assertEquals(1, r3Alerts);

              assertEquals(5, r1Ticks);
              assertEquals(5, r2Ticks);
              assertEquals(5, r3Ticks);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
