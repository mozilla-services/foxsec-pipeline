package com.mozilla.secops.parser;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;

/** Custom deserialization for payload filter implementations */
public class EventFilterPayloadDeserializer extends JsonDeserializer<EventFilterPayloadInterface> {
  @Override
  public EventFilterPayloadInterface deserialize(JsonParser jp, DeserializationContext context)
      throws IOException {
    ObjectMapper mapper = (ObjectMapper) jp.getCodec();
    ObjectNode root = mapper.readTree(jp);

    // Custom interface deserialization; if we have a payload_filters node treat this an or
    // implementation, otherwise handle it was a payload filter
    if (root.has("payload_or_filters")) {
      return mapper.readValue(root.toString(), EventFilterPayloadOr.class);
    }
    return mapper.readValue(root.toString(), EventFilterPayload.class);
  }
}
