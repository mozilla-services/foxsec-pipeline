package com.mozilla.secops.parser.models.duopull;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Duopull implements Serializable {
    private static final long serialVersionUID = 1L;

    private String eventDescriptionUserId;
    private String eventObject;
    private Long eventTimestamp;
    private String eventUsername;
    private String eventFactor;
    private String eventResult;
    private String eventReason;
    private String path;
    private String msg;
    private String eventAction;

    @JsonProperty("event_description_user_id")
    public String getEventDescriptionUserId() {
        return eventDescriptionUserId;
    }

    @JsonProperty("event_object")
    public String getEventDescriptionObject() {
        return eventObject;
    }

    @JsonProperty("event_timestamp")
    public Long getEventTimestamp() {
        return eventTimestamp;
    }

    @JsonProperty("event_username")
    public String getEventUsername() {
        return eventUsername;
    }

    @JsonProperty("path")
    public String getPath() {
        return path;
    }

    @JsonProperty("msg")
    public String getMsg() {
        return msg;
    }

    @JsonProperty("event_action")
    public String getEventAction() {
        return eventAction;
    }

    @JsonProperty("event_factor")
    public String getEventFactor() {
        return eventFactor;
    }

    @JsonProperty("event_result")
    public String getEventResult() {
        return eventResult;
    }

    @JsonProperty("event_reason")
    public String getEventReason() {
        return eventReason;
    }

    public Duopull() {
    }
}
