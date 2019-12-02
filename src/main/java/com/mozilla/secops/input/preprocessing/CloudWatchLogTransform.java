package com.mozilla.secops.input.preprocessing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.models.cloudwatch.CloudWatchLogSubscription;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/**
 * {@link DoFn} for preprocessing Cloudwatch Logs so each log event is a seperate output with
 * metadata (which loggroup it is a part of)
 */
public class CloudWatchLogTransform extends PTransform<PCollection<String>, PCollection<String>> {

  private static final long serialVersionUID = 1L;
  ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public PCollection<String> expand(PCollection<String> input) {
    return input
        .apply(ParDo.of(new SerializeSubscription()))
        .apply(ParDo.of(new DataMessageFilter()))
        .apply(ParDo.of(new ExtractLogEvents()));
  }

  class SerializeSubscription extends DoFn<String, CloudWatchLogSubscription> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void processElement(ProcessContext c) {
      String json = c.element();

      try {
        CloudWatchLogSubscription cws =
            objectMapper.readValue(json, CloudWatchLogSubscription.class);
        c.output(cws);
      } catch (IOException e) {
        // pass
      }
    }
  }

  class DataMessageFilter extends DoFn<CloudWatchLogSubscription, CloudWatchLogSubscription> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void ProcessElement(ProcessContext c) {
      CloudWatchLogSubscription cws = c.element();
      if (cws.isDataMessage()) {
        c.output(cws);
      }
    }
  }

  class ExtractLogEvents extends DoFn<CloudWatchLogSubscription, String> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void ProcessElement(ProcessContext c) {
      CloudWatchLogSubscription cws = c.element();
      ArrayList<Object> logEvents = cws.getLogEvents();
      for (Object logEvent : logEvents) {
        try {
          String event = objectMapper.writeValueAsString(logEvent);
          c.output(event);
        } catch (JsonProcessingException e) {
          // pass
        }
      }
    }
  }
}
