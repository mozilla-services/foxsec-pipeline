package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.models.aws.cloudwatch.CloudWatchEvent;
import com.mozilla.secops.parser.models.aws.guardduty.GuardDutyFinding;
import java.io.Serializable;

/** Payload parser for AWS CloudWatch Event data */
public class CloudWatch extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private ObjectMapper mapper;
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

  /** get underlying {@link GuardDutyFinding} if there is one */
  public GuardDutyFinding getGuardDutyFinding() throws Exception {
    if (!cwEvent.getDetailType().equals(GuardDutyFinding.CW_EVENT_GUARD_DUTY_DETAIL_TYPE)) {
      throw new Exception("CloudWatch event does not contain a GuardDuty finding");
    }
    try {
      return mapper.convertValue(cwEvent.getDetail(), GuardDutyFinding.class);
    } catch (Exception exc) {
      throw exc;
    }
  }

  /** Construct matcher object. */
  public CloudWatch() {}

  /**
   * Construct parser object.
   *
   * @param input Input string
   */
  public CloudWatch(String input, Event e, ParserState s) {
    mapper = new ObjectMapper();
    try {
      cwEvent = mapper.readValue(input, CloudWatchEvent.class);
    } catch (Exception exc) {
      System.out.println(exc.getMessage());
      return;
    }
  }
}
