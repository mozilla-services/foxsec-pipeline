package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.FxaAuth;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestCustomsFeatures implements Serializable {
  private static final long serialVersionUID = 1L;

  @Rule public final transient TestPipeline p = TestPipeline.create();

  @Test
  public void testCustomsFeaturesCombine() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/customs_abuse_password_reset1.txt", p);

    ParserCfg parserCfg = new ParserCfg();
    parserCfg.setXffAddressSelector(new ArrayList<>(Arrays.asList(new String[] {"127.0.0.1/32"})));

    PCollection<KV<String, CustomsFeatures>> res =
        input
            .apply(ParDo.of(new ParserDoFn().withConfiguration(parserCfg)))
            .apply(
                ParDo.of(
                    new DoFn<Event, KV<String, Event>>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        if (!c.element().getPayloadType().equals(Payload.PayloadType.FXAAUTH)) {
                          return;
                        }
                        c.output(KV.of(CustomsUtil.authGetSourceAddress(c.element()), c.element()));
                      }
                    }))
            .apply(new CustomsFeaturesCombiner());

    PAssert.that(res)
        .satisfies(
            x -> {
              int tcnt = 0;

              for (KV<String, CustomsFeatures> v : x) {
                CustomsFeatures col = v.getValue();
                if (v.getKey().equals("10.0.0.1")) {
                  assertEquals(5, col.getEvents().size());
                  assertEquals(1, col.getUniquePathRequestCount().size());
                  assertEquals(1, col.getUniquePathSuccessfulRequestCount().size());
                  assertEquals(
                      5,
                      (int) col.getUniquePathRequestCount().get("/v1/password/forgot/send_code"));
                } else if (v.getKey().equals("10.0.0.2")) {
                  assertEquals(4, col.getEvents().size());
                } else {
                  fail("unexpected key");
                }
                tcnt++;
              }
              assertEquals(2, tcnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void testCustomsFeaturesEmailKeyLoginFailure() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/customs_rl_badlogin_simple1.txt", p);

    ParserCfg parserCfg = new ParserCfg();
    parserCfg.setXffAddressSelector(new ArrayList<>(Arrays.asList(new String[] {"127.0.0.1/32"})));

    PCollection<KV<String, CustomsFeatures>> res =
        input
            .apply(ParDo.of(new ParserDoFn().withConfiguration(parserCfg)))
            .apply(
                ParDo.of(
                    new DoFn<Event, KV<String, Event>>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        if (!c.element().getPayloadType().equals(Payload.PayloadType.FXAAUTH)) {
                          return;
                        }
                        c.output(KV.of(CustomsUtil.authGetEmail(c.element()), c.element()));
                      }
                    }))
            .apply(new CustomsFeaturesCombiner());

    PAssert.that(res)
        .satisfies(
            x -> {
              int tcnt = 0;

              for (KV<String, CustomsFeatures> v : x) {
                CustomsFeatures col = v.getValue();
                if (v.getKey().equals("kirk@mozilla.com")) {
                  assertEquals(12, col.getEvents().size());
                  assertEquals(12, col.getTotalLoginFailureCount());
                  assertEquals(0, col.getTotalLoginSuccessCount());
                  assertEquals(10, col.getSourceAddressEventCount().size());
                  assertEquals(0, col.getUnknownEventCounter());
                  assertEquals(
                      12,
                      (int)
                          col.getSummarizedEventCounters().get(FxaAuth.EventSummary.LOGIN_FAILURE));
                  assertEquals(1, col.getUniquePathRequestCount().size());
                  assertEquals(0, col.getUniquePathSuccessfulRequestCount().size());
                  assertEquals(12, (int) col.getUniquePathRequestCount().get("/v1/account/login"));
                } else if (v.getKey().equals("spock@mozilla.com")) {
                  assertEquals(12, col.getEvents().size());
                  assertEquals(10, col.getTotalLoginFailureCount());
                  assertEquals(0, col.getTotalLoginSuccessCount());
                  assertEquals(12, (int) col.getSourceAddressEventCount().get("216.160.83.56"));
                  assertEquals(1, col.getSourceAddressEventCount().size());
                  // Will be 2 since two blocked requests will not be summarized
                  assertEquals(2, col.getUnknownEventCounter());
                  assertEquals(
                      10,
                      (int)
                          col.getSummarizedEventCounters().get(FxaAuth.EventSummary.LOGIN_FAILURE));
                  assertEquals(1, col.getUniquePathRequestCount().size());
                  assertEquals(0, col.getUniquePathSuccessfulRequestCount().size());
                  assertEquals(12, (int) col.getUniquePathRequestCount().get("/v1/account/login"));
                } else {
                  fail("unexpected key");
                }
                tcnt++;
              }
              assertEquals(2, tcnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
