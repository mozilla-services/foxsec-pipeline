package com.mozilla.secops.input.preprocessing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.zip.GZIPInputStream;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.commons.io.IOUtils;

public class KinesisDataDecodingTransform
    extends PTransform<PCollection<String>, PCollection<String>> {
  private static final long serialVersionUID = 1L;
  ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public PCollection<String> expand(PCollection<String> input) {
    return input.apply(ParDo.of(new DecodeKinesisData()));
  }

  class DecodeKinesisData extends DoFn<String, String> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void processElement(ProcessContext c) {
      String input = c.element();
      try {
        JsonNode jsonNode = objectMapper.readTree(input);
        JsonNode awsLogs = jsonNode.get("awslogs");
        if (awsLogs != null) {
          JsonNode data = awsLogs.get("data");
          if (data != null && data.isValueNode()) {
            Decoder decoder = Base64.getDecoder();
            byte[] decoded = decoder.decode(data.asText());
            GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(decoded));
            StringWriter writer = new StringWriter();
            IOUtils.copy(gis, writer, StandardCharsets.UTF_8.name());
            String s = writer.toString();
            c.output(s);
            return;
          }
        }
        c.output(input);
      } catch (IOException e) {
        c.output(input);
      }
    }
  }
}
