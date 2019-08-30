package com.mozilla.secops.input;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.Raw;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestInputTypeFileMulti {
  public TestInputTypeFileMulti() {}

  private static InputOptions getInputOptions() {
    InputOptions o = PipelineOptionsFactory.as(InputOptions.class);
    o.setInputFile(
        new String[] {
          "./target/test-classes/testdata/inputtype_buffer1.txt",
          "./target/test-classes/testdata/inputtype_buffer2.txt"
        });
    return o;
  }

  @Rule public final transient TestPipeline pipeline = TestPipeline.fromOptions(getInputOptions());

  @Test
  public void noopTextPipelineTest() throws Exception {
    pipeline.run().waitUntilFinish();
  }

  @Test
  public void readTextTest() throws Exception {
    InputOptions o = (InputOptions) pipeline.getOptions();

    PCollection<String> results = pipeline.apply(Input.compositeInputAdapter(o, null));
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(30L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void readTextTestParsingElement() throws Exception {
    Input input =
        new Input()
            .simplex()
            .withInputElement(
                new InputElement(Input.SIMPLEX_DEFAULT_ELEMENT)
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer1.txt")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer2.txt")
                    .setParserConfiguration(new ParserCfg()));

    PCollection<Event> results = pipeline.apply(input.simplexRead());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(30L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void readTextTestMultiElement() throws Exception {
    Input input =
        new Input()
            .multiplex()
            .withInputElement(
                new InputElement("a")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer1.txt"))
            .withInputElement(
                new InputElement("b")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer2.txt"));

    PCollection<KV<String, String>> results = pipeline.apply(input.multiplexReadRaw());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(30L);

    PAssert.that(results)
        .satisfies(
            i -> {
              int a = 0;
              int b = 0;
              for (KV<String, String> v : i) {
                if (v.getKey().equals("a")) {
                  a++;
                } else if (v.getKey().equals("b")) {
                  b++;
                } else {
                  fail("unexpected key");
                }
              }
              assertEquals(10, a);
              assertEquals(20, b);
              return null;
            });

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void readTextTestParsingMultiElement() throws Exception {
    Input input =
        new Input()
            .multiplex()
            .withInputElement(
                new InputElement("a")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer1.txt")
                    .setParserConfiguration(new ParserCfg()))
            .withInputElement(
                new InputElement("b")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer2.txt")
                    .setParserConfiguration(new ParserCfg()));

    PCollection<KV<String, Event>> results = pipeline.apply(input.multiplexRead());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(30L);

    PAssert.that(results)
        .satisfies(
            i -> {
              int a = 0;
              int b = 0;
              for (KV<String, Event> v : i) {
                if (v.getKey().equals("a")) {
                  a++;
                } else if (v.getKey().equals("b")) {
                  b++;
                } else {
                  fail("unexpected key");
                }
              }
              assertEquals(10, a);
              assertEquals(20, b);
              return null;
            });

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void readTextTestParsingMultiElementFilter() throws Exception {
    EventFilter filter = new EventFilter();
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

    Input input =
        new Input()
            .multiplex()
            .withInputElement(
                new InputElement("a")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt")
                    .setParserConfiguration(new ParserCfg())
                    .setEventFilter(filter))
            .withInputElement(
                new InputElement("b")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt")
                    .setParserConfiguration(new ParserCfg())
                    .setEventFilter(filter));

    PCollection<KV<String, Event>> results = pipeline.apply(input.multiplexRead());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(20L);

    PAssert.that(results)
        .satisfies(
            i -> {
              int a = 0;
              int b = 0;
              for (KV<String, Event> v : i) {
                if (v.getKey().equals("a")) {
                  a++;
                } else if (v.getKey().equals("b")) {
                  b++;
                } else {
                  fail("unexpected key");
                }
              }
              assertEquals(10, a);
              assertEquals(10, b);
              return null;
            });

    pipeline.run().waitUntilFinish();
  }
}
