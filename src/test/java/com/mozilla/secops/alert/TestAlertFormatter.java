package com.mozilla.secops.alert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.mozilla.secops.IOOptions;
import com.mozilla.secops.parser.ParserTest;
import java.util.Arrays;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestAlertFormatter {

  public TestAlertFormatter() {}

  @Rule public final transient TestPipeline p = TestPipeline.create();

  private PCollection<Alert> getTestInput(TestPipeline p) {
    Alert testAlert = new Alert();
    testAlert.addMetadata(AlertMeta.Key.SOURCEADDRESS, "216.160.83.56");
    return p.apply(Create.of(Arrays.asList(new Alert[] {testAlert})));
  }

  @Test
  public void runFormatter() {
    IOOptions options = PipelineOptionsFactory.as(IOOptions.class);
    options.setMonitoredResourceIndicator("test");
    PCollection<String> res =
        getTestInput(p)
            .apply(ParDo.of(new AlertFormatter(options)))
            .apply(MapElements.via(new AlertFormatter.AlertToString()));

    PAssert.that(res)
        .satisfies(
            results -> {
              for (String s : results) {
                Alert a = Alert.fromJSON(s);
                assertNotNull(a);
                assertNull(a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY));
                assertNull(a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void runFormatterWithSettings() {
    IOOptions options = PipelineOptionsFactory.as(IOOptions.class);
    options.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    options.setMonitoredResourceIndicator("formatter_test");

    PCollection<String> res =
        getTestInput(p)
            .apply(ParDo.of(new AlertFormatter(options)))
            .apply(MapElements.via(new AlertFormatter.AlertToString()));

    PAssert.that(res)
        .satisfies(
            results -> {
              for (String s : results) {
                Alert a = Alert.fromJSON(s);
                assertNotNull(a);
                assertEquals("216.160.83.56", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                assertEquals("Milton", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY));
                assertEquals("US", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
                assertEquals(
                    "formatter_test", a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE));
              }
              return null;
            });

    p.run().waitUntilFinish();
  }
}
