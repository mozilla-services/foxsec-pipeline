package com.mozilla.secops.input.preprocessing;

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
  private ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public PCollection<String> expand(PCollection<String> input) {
    return input.apply(ParDo.of(new NormalizeCloudWatchLogEvents()));
  }

  class NormalizeCloudWatchLogEvents extends DoFn<String, String> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void processElement(ProcessContext c) {
      String input = c.element();

      try {
        CloudWatchLogSubscription cws =
            objectMapper.readValue(input, CloudWatchLogSubscription.class);

        if (cws.getLogGroup() == null
            || cws.getLogStream() == null
            || cws.getOwner() == null
            || cws.getSubscriptionFilters() == null) {
          // if fields weren't populated output the original message
          c.output(input);
        } else {
          // if this is a data message with log events:
          // normalize the message so we have only one event per log message
          if (cws.isDataMessage() && cws.getLogEvents() != null) {
            ArrayList<CloudWatchLogSubscription> events =
                CloudWatchLogSubscription.makeSingleEventLogs(cws);
            for (CloudWatchLogSubscription event : events) {

              String normalized = objectMapper.writeValueAsString(event);
              c.output(normalized);
            }
          }
        }
      } catch (IOException exc) {
        c.output(input);
      }
    }
  }
}
