package com.mozilla.secops.input;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.Raw;
import org.junit.Test;

public class TestInputJson {
  public TestInputJson() {}

  private static ObjectMapper mapper = new ObjectMapper();

  @Test
  public void testJsonSerializeInput() throws Exception {
    EventFilter filter = new EventFilter();
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

    Input input =
        new Input("project")
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

    // XXX Expand to test read
    mapper.writeValueAsString(input);
  }
}
