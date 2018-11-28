package com.mozilla.secops.awsbehavior;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.parser.Cloudtrail;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import java.io.Serializable;
import java.util.ArrayList;

/** Translates a JSON object into an EventFilter and context for any resulting matches. */
public class CloudtrailMatcher implements Serializable {
  private static final long serialVersionUID = 1L;

  private ArrayList<ArrayList<String>> fields;
  private String description;
  private String resource;

  /**
   * Converts {@link CloudtrailMatcher} into an {@link EventFilterRule}
   *
   * @return {@link EventFilterRule}
   */
  public EventFilterRule toEventFilterRule() {
    EventFilterRule rule = new EventFilterRule();
    for (ArrayList<String> fieldMatcher : fields) {
      rule.addPayloadFilter(
          new EventFilterPayload(Cloudtrail.class)
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
      case "recipientAccountId":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_ACCOUNTID;
      case "userIdentity.invokedBy":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_INVOKEDBY;
      case "userIdentity.sessionContext.attributes.mfaAuthenticated":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_MFA;
    }

    return null;
  }
}
