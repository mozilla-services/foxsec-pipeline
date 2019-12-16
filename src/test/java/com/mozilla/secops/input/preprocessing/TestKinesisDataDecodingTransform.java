package com.mozilla.secops.input.preprocessing;

import java.util.ArrayList;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestKinesisDataDecodingTransform {

  @Rule public final transient TestPipeline pipeline = TestPipeline.create();

  @Test
  public void testUnencapsulatedMessagesAreUnaltered() {
    String data = "{\"notawsdata\": \"somevalue\"}";
    ArrayList<String> buf = new ArrayList<>();
    buf.add(data);
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new KinesisDataDecodingTransform());
    PAssert.that(output).containsInAnyOrder(data);
    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testUnencodedMessagesAreUnaltered() {
    String data = "{\"awslogs\": {\"data\": \"uncompressedunbase64eddata\"}}";
    ArrayList<String> buf = new ArrayList<>();
    buf.add(data);
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new KinesisDataDecodingTransform());
    PAssert.that(output).containsInAnyOrder(data);
    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testEncodedMessagesAreDecoded() {
    String expected = "asjkdjks";
    String data = "{\"awslogs\": {\"data\": \"H4sIAH3u810C/0sszspOycouBgDSY29dCAAAAA==\"}}";
    ArrayList<String> buf = new ArrayList<>();
    buf.add(data);
    PCollection<String> input = pipeline.apply(Create.of(buf));
    PCollection<String> output = input.apply(new KinesisDataDecodingTransform());
    PAssert.that(output).containsInAnyOrder(expected);
    pipeline.run().waitUntilFinish();
  }

}
