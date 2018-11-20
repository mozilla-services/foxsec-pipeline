package com.mozilla.secops.awsbehavior;

import com.fasterxml.jackson.annotation.JsonProperty;

import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Cloudtrail;

import java.util.Map;
import java.util.ArrayList;

/**
 * Translates a JSON object into an EventFilter
 * and metadata for the Alert
 */
public class CloudtrailMatcher {
    private ArrayList<ArrayList<String>> fields;
    private String description;
    private String resource;

    public EventFilterRule toEventFilterRule() {
        EventFilterRule rule = new EventFilterRule();
        for (ArrayList<String> fieldMatcher : fields) {
            rule.addPayloadFilter(new EventFilterPayload(Cloudtrail.class)
                    .withStringMatch(fieldToStringProperty(fieldMatcher.get(0)), fieldMatcher.get(1)));
        }
        return rule;
    }

    @JsonProperty("fields")
    public ArrayList<ArrayList<String>> getFields() {
        return fields;
    }

    @JsonProperty("description")
    public String getDescription() {
        return description;
    }

    @JsonProperty("resource")
    public String getResource() {
        return resource;
    }

    private EventFilterPayload.StringProperty fieldToStringProperty(String field) {
        switch (field) {
            case "eventName":
                return EventFilterPayload.StringProperty.CLOUDTRAIL_EVENTNAME;
            case "userIdentity":
                return EventFilterPayload.StringProperty.CLOUDTRAIL_USERIDENTITY;
            case "recipientAccountId":
                return EventFilterPayload.StringProperty.CLOUDTRAIL_ACCOUNTID;
        }
        return null;
    }
}
