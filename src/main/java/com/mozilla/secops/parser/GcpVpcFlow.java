package com.mozilla.secops.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.logging.v2.model.LogEntry;
import java.io.IOException;
import java.io.Serializable;
import java.util.Map;
import org.joda.time.DateTime;

/** Payload parser for GCP VPC flow logs */
public class GcpVpcFlow extends SourcePayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.gcpvpcflow.GcpVpcFlow data;

  @Override
  public Boolean matcher(String input, ParserState state) {
    LogEntry entry = state.getLogEntryHint();
    if (entry == null) {
      return false;
    }
    String logName = entry.getLogName();
    if ((logName != null) && (logName.endsWith("vpc_flows"))) {
      return true;
    }
    return false;
  }

  @Override
  public Payload.PayloadType getType() {
    return Payload.PayloadType.GCP_VPC_FLOW;
  }

  /** Construct matcher object. */
  public GcpVpcFlow() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public GcpVpcFlow(String input, Event e, ParserState state) {
    LogEntry entry = state.getLogEntryHint();
    if (entry == null) {
      // Reuse JacksonFactory from parser state
      GsonFactory jf = state.getGoogleJacksonFactory();
      JsonParser jp = null;
      jp = jf.createJsonParser(input);

      try {
        entry = jp.parse(LogEntry.class);
      } catch (IOException exc) {
        return;
      } finally {
        try {
          if (jp != null) {
            jp.close();
          }
        } catch (IOException jexc) {
          throw new RuntimeException(jexc.getMessage());
        }
      }

      // Since we didn't have a LogEntry hint, try to set the event timestamp from the LogEntry
      // here. Normally this occurs as part of stripping the encapsulation, so only do it if we
      // didn't have the hint value for some reason.
      String ets = entry.getTimestamp();
      if (ets != null) {
        DateTime d = Parser.parseISO8601(ets);
        if (d != null) {
          e.setTimestamp(d);
        }
      }
    }

    Map<String, Object> m = entry.getJsonPayload();
    if (m == null) {
      return;
    }
    try {
      data =
          state
              .getObjectMapper()
              .readValue(
                  state.getObjectMapper().writeValueAsString(m),
                  com.mozilla.secops.parser.models.gcpvpcflow.GcpVpcFlow.class);
    } catch (JsonProcessingException exc) {
      return;
    }
  }

  /**
   * Get bytes sent
   *
   * @return Integer
   */
  public Integer getBytesSent() {
    return data.getBytesSent();
  }

  /**
   * Get source IP
   *
   * @return String
   */
  public String getSrcIp() {
    return data.getConnection() == null ? null : data.getConnection().getSrcIp();
  }

  /**
   * Get destination IP
   *
   * @return String
   */
  public String getDestIp() {
    return data.getConnection() == null ? null : data.getConnection().getDestIp();
  }

  /**
   * Get source port
   *
   * @return Integer
   */
  public Integer getSrcPort() {
    return data.getConnection() == null ? null : data.getConnection().getSrcPort();
  }

  /**
   * Get destination port
   *
   * @return Integer
   */
  public Integer getDestPort() {
    return data.getConnection() == null ? null : data.getConnection().getDestPort();
  }

  /**
   * Get source instance name
   *
   * @return String
   */
  public String getSrcInstanceName() {
    return data.getSrcInstance() == null ? null : data.getSrcInstance().getVmName();
  }
}
