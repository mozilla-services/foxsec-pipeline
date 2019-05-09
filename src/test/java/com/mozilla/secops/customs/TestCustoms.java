package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.ParserTest;
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
    ret.setMonitoredResourceIndicator("test");
    ret.setMaxmindDbPath(ParserTest.TEST_GEOIP_DBPATH);
    return ret;
  }

  public TestCustoms() {}

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

  @Test
  public void parseTest() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/customs_rl_badlogin_simple1.txt", p);

    PCollection<Long> count =
        input
            .apply(ParDo.of(new ParserDoFn()))
            .apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.thatSingleton(count).isEqualTo(5L);

    p.run().waitUntilFinish();
  }

  @Test
  public void rlLoginFailureSourceAddressTest() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/customs_rl_badlogin_simple1.txt", p);

    CustomsCfg cfg = CustomsCfg.loadFromResource("/customs/customsdefault.json");
    // Force use of event timestamp for testing purposes
    cfg.setTimestampOverride(true);

    PCollection<Alert> alerts = Customs.executePipeline(p, input, getTestOptions());

    PCollection<Long> count =
        alerts.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int cnt = 0;
              for (Alert a : x) {
                assertEquals("customs", a.getCategory());
                assertEquals("spock@mozilla.com", a.getMetadataValue("accountid"));
                assertEquals("127.0.0.1", a.getMetadataValue("sourceaddress"));
                assertEquals("5", a.getMetadataValue("count"));
                assertEquals("3", a.getMetadataValue("threshold"));
                assertEquals(
                    "rl_login_failure_sourceaddress_accountid",
                    a.getMetadataValue("customs_category"));
                assertEquals("1970-01-01T00:00:00.000Z", a.getTimestamp().toString());
                assertEquals(
                    "test login failure rate violation, spock@mozilla.com from 127.0.0.1",
                    a.getSummary());
                assertEquals(
                    "test login failure rate violation, <<masked>> from 127.0.0.1",
                    a.getMetadataValue("masked_summary"));
                cnt++;
              }
              assertEquals(1, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void rlLoginFailureSourceAddressTestStream() throws Exception {
    CustomsCfg cfg = CustomsCfg.loadFromResource("/customs/customsdefault.json");
    // Force use of event timestamp for testing purposes
    cfg.setTimestampOverride(true);

    String[] eb1 = TestUtil.getTestInputArray("/testdata/customs_rl_badlogin_simple1.txt");
    String[] eb2 = TestUtil.getTestInputArray("/testdata/customs_rl_badlogin_simple2.txt");
    String[] eb3 = TestUtil.getTestInputArray("/testdata/customs_rl_badlogin_simple3.txt");
    TestStream<String> s =
        TestStream.create(StringUtf8Coder.of())
            .advanceWatermarkTo(new Instant(0L))
            .addElements(eb1[0], Arrays.copyOfRange(eb1, 1, eb1.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(1500)))
            .addElements(eb2[0], Arrays.copyOfRange(eb2, 1, eb2.length))
            .advanceWatermarkTo(new Instant(0L).plus(Duration.standardSeconds(2500)))
            .addElements(eb3[0], Arrays.copyOfRange(eb3, 1, eb3.length))
            .advanceWatermarkToInfinity();

    PCollection<String> input = p.apply(s);
    PCollection<Alert> alerts = Customs.executePipeline(p, input, getTestOptions());

    PCollection<Long> count =
        alerts.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(count).isEqualTo(2L);

    p.run().waitUntilFinish();
  }

  @Test
  public void rlMultiTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/customs_multi1.txt", p);

    CustomsCfg cfg = CustomsCfg.loadFromResource("/customs/customsdefault.json");
    // Force use of event timestamp for testing purposes
    cfg.setTimestampOverride(true);

    PCollection<Alert> alerts = Customs.executePipeline(p, input, getTestOptions());

    PCollection<Long> count =
        alerts.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(count).isEqualTo(6L);

    p.run().waitUntilFinish();
  }

  @Test
  public void accountCreationAbuseTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/customs_createacctabuse.txt", p);

    CustomsCfg cfg = CustomsCfg.loadFromResource("/customs/customsdefault.json");
    // Force use of event timestamp for testing purposes
    cfg.setTimestampOverride(true);

    Customs.CustomsOptions options = getTestOptions();
    options.setEnableRateLimitDetectors(false);
    options.setEnableAccountCreationAbuseDetector(true);
    options.setXffAddressSelector("127.0.0.1/32");

    PCollection<Alert> alerts = Customs.executePipeline(p, input, options);

    PCollection<Long> count =
        alerts.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.thatSingleton(count).isEqualTo(1L);

    PAssert.that(alerts)
        .satisfies(
            x -> {
              int cnt = 0;
              for (Alert a : x) {
                assertEquals("customs", a.getCategory());
                assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
                assertEquals("3", a.getMetadataValue("count"));
                assertEquals("account_creation_abuse", a.getMetadataValue("customs_category"));
                assertEquals("test suspicious account creation, 216.160.83.56 3", a.getSummary());
                cnt++;
              }
              assertEquals(1, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
