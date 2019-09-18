package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.ParserTest;
import com.mozilla.secops.window.GlobalTriggers;
import java.util.Arrays;
import org.apache.beam.sdk.coders.StringUtf8Coder;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.TestStream;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestCustoms {
  @Rule public final transient TestPipeline p = TestPipeline.create();

  private Customs.CustomsOptions getTestOptions() {
    Customs.CustomsOptions ret = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    ret.setUseEventTimestamp(true);
    ret.setMonitoredResourceIndicator("test");
    ret.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    return ret;
  }

  public TestCustoms() {}

  @Test
  public void parseTest() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/customs_rl_badlogin_simple1.txt");

    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    PCollection<Long> count =
        p.apply(s)
            .apply(ParDo.of(new ParserDoFn()))
            .apply(new GlobalTriggers<Event>(5))
            .apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count).isEqualTo(12L);

    p.run().waitUntilFinish();
  }

  @Test
  public void accountCreationAbuseTest() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/customs_createacctabuse.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/customs_rl_badlogin_simple1.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceProcessingTime(Duration.standardSeconds(60))
            // Add some unrelated elements for the second component
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceProcessingTime(Duration.standardSeconds(60))
            .advanceWatermarkToInfinity();

    Customs.CustomsOptions options = getTestOptions();
    options.setEnableAccountCreationAbuseDetector(true);
    options.setAccountCreationSessionLimit(3);
    options.setXffAddressSelector("127.0.0.1/32");
    options.setGenerateConfigurationTicksInterval(1);
    options.setGenerateConfigurationTicksMaximum(5L);

    Input input = TestCustomsUtil.wiredInputStream(options, s);

    PCollection<Alert> alerts =
        Customs.executePipeline(p, p.apply(input.simplexReadRaw()), options);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int alertCnt = 0;
              int totalCnt = 0;
              for (Alert a : x) {
                totalCnt++;
                if (a.getCategory().equals("customs")) {
                  assertEquals("customs", a.getCategory());
                  assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                  assertEquals("3", a.getMetadataValue("count"));
                  assertEquals("account_creation_abuse", a.getMetadataValue("customs_category"));
                  assertEquals("test suspicious account creation, 216.160.83.56 3", a.getSummary());
                  alertCnt++;
                }
              }
              assertEquals(1, alertCnt);
              assertEquals(6, totalCnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void accountCreationAbuseTestDist() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/customs_createacctabuse_dist.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Customs.CustomsOptions options = getTestOptions();
    options.setEnableAccountCreationAbuseDetector(true);
    options.setXffAddressSelector("127.0.0.1/32");
    // Increase session creation limit here so we don't trip an alert for that as part of
    // the same address component of the test
    options.setAccountCreationSessionLimit(10);

    PCollection<Alert> alerts = Customs.executePipeline(p, p.apply(s), options);

    PCollection<Long> count =
        alerts.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(count).isEqualTo(6L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int cnt = 0;
              for (Alert a : x) {
                if (!a.getMetadataValue("sourceaddress").equals("216.160.83.56")) {
                  continue;
                }
                assertEquals("customs", a.getCategory());
                assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                assertEquals("6", a.getMetadataValue("count"));
                assertEquals("user3@mail.com", a.getMetadataValue("email"));
                assertEquals(
                    "account_creation_abuse_distributed", a.getMetadataValue("notify_merge"));
                assertEquals(
                    "account_creation_abuse_distributed", a.getMetadataValue("customs_category"));
                assertEquals(
                    "test suspicious distributed account creation, 216.160.83.56 6",
                    a.getSummary());
                cnt++;
              }
              assertEquals(1, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void sourceLoginFailureTest() throws Exception {
    String[] eb1 = TestUtil.getTestInputArray("/testdata/customs_rl_badlogin_simple1.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkToInfinity();

    Customs.CustomsOptions options = getTestOptions();
    options.setEnableSourceLoginFailureDetector(true);
    options.setSourceLoginFailureThreshold(10);
    options.setXffAddressSelector("127.0.0.1/32");

    PCollection<Alert> alerts = Customs.executePipeline(p, p.apply(s), options);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int cnt = 0;
              for (Alert a : x) {
                System.out.println(a.toJSON());
                assertEquals("customs", a.getCategory());
                assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                // Should be 10, since two events have a blocked errno and shouldn't be factored in
                assertEquals("10", a.getMetadataValue("count"));
                assertEquals("spock@mozilla.com", a.getMetadataValue("email"));
                assertEquals("source_login_failure", a.getMetadataValue("notify_merge"));
                assertEquals("source_login_failure", a.getMetadataValue("customs_category"));
                assertEquals(
                    "test source login failure threshold exceeded, 216.160.83.56 10 in 300 seconds",
                    a.getSummary());
                cnt++;
              }
              assertEquals(1, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
