package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.models.aws.cloudwatch.CloudWatchEvent;
import java.io.Serializable;

/** Payload parser for AWS CloudWatch Event data */
public class CloudWatch extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private CloudWatchEvent cwEvent;

  @Override
  public Boolean matcher(String input, ParserState state) {
    return (input.contains("aws.guardduty"));
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.CLOUDWATCH;
  }

  /** get underlying {@link CloudWatchEvent} */
  public CloudWatchEvent getEvent() {
    return cwEvent;
  }

  /** Construct matcher object. */
  public CloudWatch() {}

  /**
   * Construct parser object.
   *
   * @param input Input string
   */
  public CloudWatch(String input, Event e, ParserState s) {
    try {
      ObjectMapper mapper = new ObjectMapper();
      cwEvent =
          mapper.readValue(
              input, com.mozilla.secops.parser.models.aws.cloudwatch.CloudWatchEvent.class);
    } catch (Exception exc) {
      System.out.println(exc.getMessage());
      return;
    }
  }
}
