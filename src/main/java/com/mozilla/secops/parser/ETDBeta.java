package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.services.logging.v2.model.LogEntry;
import com.mozilla.secops.parser.models.etd.EventThreatDetectionFinding;
import java.io.IOException;
import java.io.Serializable;

/** Payload parser for GCP ETD Finding data */
public class ETDBeta extends PayloadBase implements Serializable {

  private static final long serialVersionUID = 1L;

  /** StackDriver log resource type for an ETD Finding */
  public static final String STACKDRIVER_LOG_RESOURCE_TYPE = "threat_detector";

  private static ObjectMapper mapper = new ObjectMapper();

  private EventThreatDetectionFinding etdf;

  @Override
  public Boolean matcher(String input, ParserState state) {
    LogEntry le = state.getLogEntryHint();
    if ((le != null) && (le.getResource() != null) && (le.getResource().getType() != null)) {
      return le.getResource().getType().equals(STACKDRIVER_LOG_RESOURCE_TYPE);
    }
    // we do not expect to get ETD Findings outside of a Stackdriver log
    // wrapper, and thus we do not expect to reach the code below often
    //
    // It is included as an effort to maintain consistent behavior across the parsers
    try {
      EventThreatDetectionFinding f = mapper.readValue(input, EventThreatDetectionFinding.class);
      return ((f != null) && (f.getDetectionPriority() != null) && (f.getEventTime() != null));
    } catch (IOException exc) {
      return false;
    }
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.ETD;
  }

  /**
   * Get underlying EventThreatDetectionFinding model
   *
   * @return {@link EventThreatDetectionFinding}
   */
  public EventThreatDetectionFinding getFinding() {
    return etdf;
  }

  /** Construct matcher object. */
  public ETDBeta() {}

  /**
   * Construct parser object.
   *
   * @param input Input string
   * @param e Parent {@link Event}
   * @param s State {@link ParserState}
   */
  public ETDBeta(String input, Event e, ParserState s) {

    // try to parse from a stack driver log
    try {
      LogEntry entry = s.getLogEntryHint();
      if ((entry != null) && (entry.getJsonPayload() != null)) {
        etdf =
            mapper.readValue(
                mapper.writeValueAsString(entry.getJsonPayload()),
                EventThreatDetectionFinding.class);
        return;
      }
    } catch (IOException exc) {
      // pass
    }

    // try to parse raw input
    try {
      etdf = mapper.readValue(input, EventThreatDetectionFinding.class);
      return;
    } catch (IOException exc) {
      // pass
    }

    return;
  }
}
