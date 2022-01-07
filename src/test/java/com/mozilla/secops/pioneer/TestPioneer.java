package com.mozilla.secops.pioneer;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.input.InputElement;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestPioneer {
  @Rule public final transient TestPipeline p = TestPipeline.create();

  private Pioneer.PioneerOptions getTestOptions() {
    Pioneer.PioneerOptions ret = PipelineOptionsFactory.as(Pioneer.PioneerOptions.class);
    ret.setUseEventTimestamp(true); // Use timestamp from events for our testing
    ret.setMonitoredResourceIndicator("test");
    ret.setGenerateConfigurationTicksInterval(1);
    ret.setGenerateConfigurationTicksMaximum(5L);
    return ret;
  }

  @Test
  public void pioneerExfiltration() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/pioneer/exfiltration1.txt");

    Pioneer.PioneerOptions options = getTestOptions();

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    InputElement e =
        new InputElement(options.getMonitoredResourceIndicator())
            .addWiredStream(s)
            .setConfigurationTicks(
                Pioneer.buildConfigurationTick(options),
                options.getGenerateConfigurationTicksInterval(),
                options.getGenerateConfigurationTicksMaximum());

    PCollection<String> input =
        p.apply(
            "input",
            new Input(options.getProject()).simplex().withInputElement(e).simplexReadRaw());

    PCollection<Alert> results = Pioneer.executePipeline(p, input, options);

    PAssert.that(results)
        .satisfies(
            i -> {
              int tickcnt = 0;
              int totalcnt = 0;
              int alertcnt = 0;
              for (Alert a : i) {
                if (a.getCategory().equals("pioneer-cfgtick")) {
                  tickcnt++;
                } else {
                  assertEquals("exfiltration", a.getSubcategory());
                  assertEquals("exfiltration", a.getNotifyMergeKey());
                  assertEquals(
                      "test <!channel> data exfiltration 192.168.1.1:22 -> 10.0.0.1:40000 "
                          + "1000009000 bytes (instancename)",
                      a.getSummary());
                  assertEquals("192.168.1.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                  assertEquals("1000009000", a.getMetadataValue(AlertMeta.Key.BYTES));
                  assertEquals("2020-01-01T00:02:00.000Z", a.getMetadataValue(AlertMeta.Key.START));
                  assertEquals("2020-01-01T00:18:00.000Z", a.getMetadataValue(AlertMeta.Key.END));
                  assertEquals("instancename", a.getMetadataValue(AlertMeta.Key.INSTANCE_NAME));
                  alertcnt++;
                }
                totalcnt++;
              }
              assertEquals(5, tickcnt);
              assertEquals(6, totalcnt);
              assertEquals(1, alertcnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void pioneerExfiltration2() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/pioneer/exfiltration2a.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/pioneer/exfiltration2b.txt");
    String[] eb3 = TestUtil.getTestInputArray("/testdata/pioneer/exfiltration2c.txt");

    Pioneer.PioneerOptions options = getTestOptions();

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardMinutes(8)))
            .advanceProcessingTime(Duration.standardMinutes(8))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardMinutes(14)))
            .advanceProcessingTime(Duration.standardMinutes(14))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    InputElement e =
        new InputElement(options.getMonitoredResourceIndicator())
            .addWiredStream(s)
            .setConfigurationTicks(
                Pioneer.buildConfigurationTick(options),
                options.getGenerateConfigurationTicksInterval(),
                options.getGenerateConfigurationTicksMaximum());

    PCollection<String> input =
        p.apply(
            "input",
            new Input(options.getProject()).simplex().withInputElement(e).simplexReadRaw());

    PCollection<Alert> results = Pioneer.executePipeline(p, input, options);

    PAssert.that(results)
        .satisfies(
            i -> {
              int tickcnt = 0;
              int totalcnt = 0;
              int alertcnt = 0;
              for (Alert a : i) {
                if (a.getCategory().equals("pioneer-cfgtick")) {
                  tickcnt++;
                } else {
                  if (a.getMetadataValue(AlertMeta.Key.BYTES).equals("1000006000")) {
                    assertEquals("exfiltration", a.getSubcategory());
                    assertEquals("exfiltration", a.getNotifyMergeKey());
                    assertEquals(
                        "test <!channel> data exfiltration 192.168.1.1:22 -> 10.0.0.1:40000 "
                            + "1000006000 bytes (instancename)",
                        a.getSummary());
                    assertEquals("192.168.1.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    assertEquals("1000006000", a.getMetadataValue(AlertMeta.Key.BYTES));
                    assertEquals(
                        "2020-01-01T00:02:00.000Z", a.getMetadataValue(AlertMeta.Key.START));
                    assertEquals("2020-01-01T00:18:00.000Z", a.getMetadataValue(AlertMeta.Key.END));
                    assertEquals("instancename", a.getMetadataValue(AlertMeta.Key.INSTANCE_NAME));
                    alertcnt++;
                  } else {
                    assertEquals("exfiltration", a.getSubcategory());
                    assertEquals("exfiltration", a.getNotifyMergeKey());
                    assertEquals(
                        "test <!channel> data exfiltration 192.168.1.1:22 -> 10.0.0.1:40000 "
                            + "1000004000 bytes (instancename)",
                        a.getSummary());
                    assertEquals("192.168.1.1", a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS));
                    assertEquals("1000004000", a.getMetadataValue(AlertMeta.Key.BYTES));
                    assertEquals(
                        "2020-01-01T00:02:00.000Z", a.getMetadataValue(AlertMeta.Key.START));
                    assertEquals("2020-01-01T00:08:00.000Z", a.getMetadataValue(AlertMeta.Key.END));
                    assertEquals("instancename", a.getMetadataValue(AlertMeta.Key.INSTANCE_NAME));
                    alertcnt++;
                  }
                }
                totalcnt++;
              }
              assertEquals(5, tickcnt);
              assertEquals(7, totalcnt);
              assertEquals(2, alertcnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
