package com.mozilla.secops.awsbehavior;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.parser.Cloudtrail;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Payload;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.regex.PatternSyntaxException;

/** Translates a JSON object into an EventFilter and context for any resulting matches. */
public class CloudtrailMatcher implements Serializable {
  private static final long serialVersionUID = 1L;

  private ArrayList<ArrayList<String>> fields;
  private String description;
  private String resource;

  class UnknownStringPropertyException extends Exception {
    private static final long serialVersionUID = 1L;
  }

  /**
   * Converts {@link CloudtrailMatcher} into an {@link EventFilterRule} as regex matchers.
   *
   * @return {@link EventFilterRule}
   */
  public EventFilterRule toEventFilterRule()
      throws UnknownStringPropertyException, PatternSyntaxException {
    EventFilterRule rule = new EventFilterRule();
    rule.wantSubtype(Payload.PayloadType.CLOUDTRAIL);
    for (ArrayList<String> fieldMatcher : fields) {
      EventFilterPayload.StringProperty sp = fieldToStringProperty(fieldMatcher.get(0));
      rule.addPayloadFilter(
          new EventFilterPayload(Cloudtrail.class).withStringRegexMatch(sp, fieldMatcher.get(1)));
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

  private EventFilterPayload.StringProperty fieldToStringProperty(String field)
      throws UnknownStringPropertyException {
    switch (field) {
      case "eventName":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_EVENTNAME;
      case "eventSource":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_EVENTSOURCE;
      case "recipientAccountId":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_ACCOUNTID;
      case "userIdentity.invokedBy":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_INVOKEDBY;
      case "userIdentity.sessionContext.attributes.mfaAuthenticated":
        return EventFilterPayload.StringProperty.CLOUDTRAIL_MFA;
    }

    throw new UnknownStringPropertyException();
  }
}
