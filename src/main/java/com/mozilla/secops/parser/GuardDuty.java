package com.mozilla.secops.parser;

import com.amazonaws.services.guardduty.model.Finding;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.models.cloudwatch.CloudWatchEvent;
import java.io.IOException;
import java.io.Serializable;

/** Payload parser for AWS GuardDuty Finding data */
public class GuardDuty extends PayloadBase implements Serializable {

  private static final long serialVersionUID = 1L;
  private static final String CLOUDWATCH_EVENT_SOURCE = "aws.guardduty";

  private static ObjectMapper mapper =
      new ObjectMapper()
          // our input JSON may have properties not represented in {@link Finding} e.g. ignore
          // errors such as 'Unrecognized field "affectedResources"....'
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  private Finding gdf;

  @Override
  public Boolean matcher(String input, ParserState state) {
    CloudWatchEvent cwe = state.getCloudWatchEvent();
    if (cwe != null && cwe.getSource() != null) {
      return (cwe.getSource().equals(CLOUDWATCH_EVENT_SOURCE));
    }
    // we do not expect to get GuardDuty Findings outside of a CloudWatchEvent event
    // wrapper, and thus we do not expect to reach the code below often
    //
    // It is included as an effort to maintain consistent behavior across the parsers
    try {
      Finding f = mapper.readValue(input, Finding.class);
      // the AWS GD Finding JSON model does not have -ANY- mandatory JSON fields, and thus we
      // check that the finding has certain GuardDuty-specific fields set.
      // Not doing so results in a generic JSON payload successfully being read onto a Finding.
      // All Findings will contain an associated finding type, ARN, account ID, title, and
      // description
      return ((f != null)
          && (f.getType() != null)
          && (f.getArn() != null)
          && (f.getAccountId() != null)
          && (f.getTitle() != null)
          && (f.getDescription() != null));
    } catch (IOException exc) {
      return false;
    }
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.GUARDDUTY;
  }

  /**
   * Get underlying GuardDuty Finding
   *
   * @return {@link Finding}
   */
  public Finding getFinding() {
    return gdf;
  }

  /** Construct matcher object. */
  public GuardDuty() {}

  /**
   * Construct parser object.
   *
   * @param input Input string
   * @param e Event
   * @param s ParserState
   */
  public GuardDuty(String input, Event e, ParserState s) {
    try {
      gdf = mapper.readValue(input, Finding.class);
    } catch (IOException exc) {
      // pass
    }
    return;
  }
}
