package com.mozilla.secops;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import java.util.ArrayList;
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

    PCollection<KV<String, Boolean>> results = input.apply(new DetectNat());

    ArrayList<KV<String, Boolean>> expected = new ArrayList<>();
    expected.add(KV.of("192.168.1.1", true));
    PAssert.that(results).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }
}
