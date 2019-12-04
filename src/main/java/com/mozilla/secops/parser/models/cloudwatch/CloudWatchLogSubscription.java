package com.mozilla.secops.parser.models.cloudwatch;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import java.io.Serializable;
import java.util.ArrayList;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CloudWatchLogSubscription implements Serializable {
  private static final long serialVersionUID = 1L;


  private MessageType messageType;
  private String owner;
  private String logGroup;
  private String logStream;
  private ArrayList<String> subscriptionFilters;
  private ArrayList<Object> logEvents;

  enum MessageType {
    DATA_MESSAGE("DATA_MESSAGE"),
    CONTROL_MESSAGE("CONTROL_MESSAGE");

    private String value;

    @JsonValue
    public String getValue() {
      return value;
    }

    @JsonCreator
    public static MessageType forValue(String messageType) {
      for (MessageType m : MessageType.values()) {
        if (m.getValue().equals(messageType)) {
          return m;
        }
      }
      return null;
    }

    private MessageType(String value) {
      this.value = value;
    }
  }

  @JsonProperty("messageType")
  public MessageType getMessageType() {
    return messageType;
  }

  @JsonProperty("owner")
  public String getOwner() {
    return owner;
  }

  @JsonProperty("logGroup")
  public String getLogGroup() {
    return logGroup;
  }

  @JsonProperty("logStream")
  public String getLogStream() {
    return logStream;
  }

  @JsonProperty("subscriptionFilters")
  public ArrayList<String> getSubscriptionFilters() {
    return subscriptionFilters;
  }

  @JsonProperty("logEvents")
  public ArrayList<Object> getLogEvents() {
    return logEvents;
  }

  public boolean isDataMessage() {
    return messageType.equals(MessageType.DATA_MESSAGE);
  }
}
