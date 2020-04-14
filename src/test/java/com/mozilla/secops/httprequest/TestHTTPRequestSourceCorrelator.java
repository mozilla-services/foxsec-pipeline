package com.mozilla.secops.httprequest;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.parser.ParserTest;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestHTTPRequestSourceCorrelator {
  public TestHTTPRequestSourceCorrelator() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private HTTPRequest.HTTPRequestOptions getTestOptions() {
    HTTPRequest.HTTPRequestOptions ret =
        PipelineOptionsFactory.as(HTTPRequest.HTTPRequestOptions.class);
    ret.setUseEventTimestamp(true);
    ret.setAnalysisThresholdModifier(1.0);
    ret.setRequiredMinimumAverage(1.0);
    ret.setEnableThresholdAnalysis(true);
    ret.setMonitoredResourceIndicator("test");
    ret.setIgnoreInternalRequests(false); // Tests use internal subnets
    ret.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    ret.setMaxmindIspDbPath(ParserTest.TEST_ISP_DBPATH);
    ret.setEnableSourceCorrelator(true);
    ret.setSourceCorrelatorMinimumAddresses(2);
    ret.setInputFile(new String[] {"./target/test-classes/testdata/httpreq_sourcecorrelator1.txt"});
    return ret;
  }

  @Test
  public void sourceCorrelatorTest() throws Exception {
    HTTPRequest.HTTPRequestOptions options = getTestOptions();

    String[] eb1 = TestUtil.getTestInputArray("/testdata/httpreq_sourcecorrelator1.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Input input = HTTPRequestUtil.wiredInputStream(options, s);

    PCollection<Alert> results =
        HTTPRequest.expandInputMap(p, HTTPRequest.readInput(p, input, options), options);

    PCollection<Long> resultCount =
        results.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    // Should have two alerts, and one source correlation alert
    PAssert.thatSingleton(resultCount).isEqualTo(3L);

    PAssert.that(results)
        .satisfies(
            i -> {
              int cnt = 0;
              for (Alert a : i) {
                if (!a.getMetadataValue(AlertMeta.Key.CATEGORY).equals("isp_source_correlation")) {
                  continue;
                }
                cnt++;
                assertEquals("Century Link", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_ISP));
                assertEquals("2", a.getMetadataValue(AlertMeta.Key.TOTAL_ADDRESS_COUNT));
                assertEquals("2", a.getMetadataValue(AlertMeta.Key.TOTAL_ALERT_COUNT));
                assertEquals(
                    "test isp_source_correlation", a.getMetadataValue(AlertMeta.Key.NOTIFY_MERGE));
                assertEquals(
                    "test httprequest isp_source_correlation \"Century Link\", 2 alerting addre"
                        + "sses out of 2 observed",
                    a.getSummary());
              }
              assertEquals(1, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
