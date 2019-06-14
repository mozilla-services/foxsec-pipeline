package com.mozilla.secops.parser;

import com.amazonaws.services.guardduty.model.Finding;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.Serializable;

/** Payload parser for AWS GuardDuty Finding data */
public class GuardDuty extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private Finding gdf;

  @Override
  public Boolean matcher(String input, ParserState state) {
    return (input.contains("schemaVersion") && input.contains("title"));
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.GUARDDUTY;
  }

  /** get underlying {@link Finding} */
  public Finding getFinding() {
    return gdf;
  }

  /** Construct matcher object. */
  public GuardDuty() {}

  /**
   * Construct parser object.
   *
   * @param input Input string
   */
  public GuardDuty(String input, Event e, ParserState s) {
    ObjectMapper mapper = new ObjectMapper();

    // our input JSON may have properties not represented in AWS SDK's Class :(
    // e.g. ignore errors such as 'Unrecognized field "affectedResources"....'
    mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    try {
      gdf = mapper.readValue(input, Finding.class);
    } catch (Exception exc) {
      System.out.println(exc.getMessage());
      return;
    }
  }
}
