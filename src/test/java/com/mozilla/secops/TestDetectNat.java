package com.mozilla.secops;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import java.util.ArrayList;
import java.util.HashMap;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.junit.Rule;
import org.junit.Test;

public class TestDetectNat {
  public TestDetectNat() {}

  @Rule public final transient TestPipeline pipeline = TestPipeline.create();

  @Test
  public void detectNatTransformTest() throws Exception {
    PCollection<Event> input =
        TestUtil.getTestInput("/testdata/detectnat1.txt", pipeline)
            .apply(ParDo.of(new ParserDoFn()))
            .apply(Window.<Event>into(FixedWindows.of(Duration.standardMinutes(1))));

    PCollection<KV<String, Boolean>> results = input.apply(DetectNat.byUserAgent());

    ArrayList<KV<String, Boolean>> expected = new ArrayList<>();
    expected.add(KV.of("192.168.1.1", true));
    PAssert.that(results).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void detectNatTransformTestWithInitialValues() throws Exception {
    HashMap<String, Boolean> initialValues = new HashMap<String, Boolean>();
    initialValues.put("192.168.1.2", true);
    PCollection<Event> input =
        TestUtil.getTestInput("/testdata/detectnat1.txt", pipeline)
            .apply(ParDo.of(new ParserDoFn()))
            .apply(Window.<Event>into(FixedWindows.of(Duration.standardMinutes(1))));
    PCollection<KV<String, Boolean>> results =
        input.apply(DetectNat.byUserAgent().withKnownGateways(initialValues));

    ArrayList<KV<String, Boolean>> expected = new ArrayList<>();
    expected.add(KV.of("192.168.1.1", true));
    expected.add(KV.of("192.168.1.2", true));
    PAssert.that(results).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void detectNatTransformTestWithInitialValuesByFile() throws Exception {
    PCollection<Event> input =
        TestUtil.getTestInput("/testdata/detectnat1.txt", pipeline)
            .apply(ParDo.of(new ParserDoFn()))
            .apply(Window.<Event>into(FixedWindows.of(Duration.standardMinutes(1))));
    PCollection<KV<String, Boolean>> results =
        input.apply(DetectNat.byUserAgent().withKnownGateways("/testdata/natutil1.txt"));

    ArrayList<KV<String, Boolean>> expected = new ArrayList<>();
    expected.add(KV.of("192.168.1.1", true));
    expected.add(KV.of("192.168.1.2", true));
    PAssert.that(results).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }
}
