package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import java.io.Serializable;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestMulti1 implements Serializable {
  private static final long serialVersionUID = 1L;

  public TestMulti1() {}

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
            .apply(ParDo.of(new AlertFormatter(options)))
            .apply(
                ParDo.of(
                    new DoFn<String, Alert>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        c.output(Alert.fromJSON(c.element()));
                      }
                    }));

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(resultCount)
        .isEqualTo(12L); // Should have two alerts and 10 configuration events

    PAssert.that(results)
        .satisfies(
            i -> {
              for (Alert a : i) {
                if (a.getMetadataValue("category").equals("hard_limit")) {
                  assertEquals("192.168.1.2", a.getMetadataValue("sourceaddress"));
                  assertEquals("hard_limit httprequest hard_limit 192.168.1.2 11", a.getSummary());
                  assertEquals(11L, Long.parseLong(a.getMetadataValue("count")));
                  assertEquals(10L, Long.parseLong(a.getMetadataValue("request_threshold")));
                  assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
                  assertEquals("hard_limit", a.getMetadataValue("monitored_resource"));
                } else if (a.getMetadataValue("category").equals("error_rate")) {
                  assertEquals("10.0.0.1", a.getMetadataValue("sourceaddress"));
                  assertEquals("error_rate httprequest error_rate 10.0.0.1 35", a.getSummary());
                  assertEquals("error_rate", a.getMetadataValue("category"));
                  assertEquals(35L, Long.parseLong(a.getMetadataValue("error_count"), 10));
                  assertEquals(30L, Long.parseLong(a.getMetadataValue("error_threshold"), 10));
                  assertEquals("1970-01-01T00:00:59.999Z", a.getMetadataValue("window_timestamp"));
                  assertEquals("error_rate", a.getMetadataValue("monitored_resource"));
                }
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
