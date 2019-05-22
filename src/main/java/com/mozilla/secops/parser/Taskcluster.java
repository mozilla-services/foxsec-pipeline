package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Serializable;

/** Payload parser for Taskcluster log data */
public class Taskcluster extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.taskcluster.Taskcluster data;

  @Override
  public Boolean matcher(String input, ParserState state) {
    ObjectMapper mapper = new ObjectMapper();
    com.mozilla.secops.parser.models.taskcluster.Taskcluster d;
    try {
      d = mapper.readValue(input, com.mozilla.secops.parser.models.taskcluster.Taskcluster.class);
    } catch (IOException exc) {
      return false;
    }
    Mozlog m = state.getMozlogHint();
    if (m == null) {
      return false;
    }
    String logger = m.getLogger();
    if (logger == null) {
      return false;
    }
    if (logger.startsWith("taskcluster.")) {
      return true;
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.TASKCLUSTER;
  }

  /**
   * Fetch parsed Taskcluster data
   *
   * @return Taskcluster data
   */
  @JsonProperty("taskcluster_data")
  public com.mozilla.secops.parser.models.taskcluster.Taskcluster getTaskclusterData() {
    return data;
  }

  /**
   * Set Taskcluster data element
   *
   * @param data Taskcluster data element
   */
  public void setTaskclusterData(com.mozilla.secops.parser.models.taskcluster.Taskcluster data) {
    this.data = data;
  }

  /** Construct matcher object. */
  public Taskcluster() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public Taskcluster(String input, Event e, ParserState state) {
    ObjectMapper mapper = new ObjectMapper();
    try {
      data =
          mapper.readValue(input, com.mozilla.secops.parser.models.taskcluster.Taskcluster.class);
    } catch (IOException exc) {
      return;
    }
  }
}
