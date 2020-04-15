package com.mozilla.secops;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
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
        input.apply(DetectNat.byUserAgent().withKnownGateways("/testdata/detectnatlist1.txt"));

    ArrayList<KV<String, Boolean>> expected = new ArrayList<>();
    expected.add(KV.of("192.168.1.1", true));
    expected.add(KV.of("192.168.1.2", true));
    PAssert.that(results).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void TestGivenNullPathReturnsEmptyMap() {
    Map<String, Boolean> gwList = DetectNat.loadGatewayList(null);
    assertTrue(gwList.isEmpty());
  }

  @Test
  public void TestGivenEmptyPathReturnsEmptyMap() {
    Map<String, Boolean> gwList = DetectNat.loadGatewayList("");
    assertTrue(gwList.isEmpty());
  }

  @Test
  public void TestGivenInvalidPathReturnsEmptyMap() {
    Map<String, Boolean> gwList = DetectNat.loadGatewayList("not/a/path");
    assertTrue(gwList.isEmpty());
  }

  @Test
  public void TestGivenValidPathReturnMapWithAllItemsSingle() {
    Map<String, Boolean> gwList = DetectNat.loadGatewayList("/testdata/detectnatlist1.txt");
    assertEquals(1, gwList.size());
    assertTrue(gwList.get("192.168.1.2"));
  }

  @Test
  public void TestGivenValidPathReturnMapWithAllItemsMany() {
    Map<String, Boolean> gwList = DetectNat.loadGatewayList("/testdata/detectnatlist2.txt");
    assertEquals(3, gwList.size());
    assertTrue(gwList.get("192.168.0.0"));
    assertTrue(gwList.get("10.0.0.0"));
    assertTrue(gwList.get("255.255.255.255"));
  }
}
