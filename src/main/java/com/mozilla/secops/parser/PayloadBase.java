package com.mozilla.secops.parser;

import static com.fasterxml.jackson.annotation.JsonSubTypes.Type;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/** Base class for payloads */
@JsonTypeInfo(
  use = JsonTypeInfo.Id.NAME,
  include = JsonTypeInfo.As.PROPERTY,
  property = "type_descriptor"
)
@JsonSubTypes({
  @Type(value = SecEvent.class, name = "secevent"),
  @Type(value = Raw.class, name = "raw"),
  @Type(value = Duopull.class, name = "duopull")
})
public abstract class PayloadBase {
  /** Construct matcher object. */
  public PayloadBase() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param p Parser instance.
   */
  public PayloadBase(String input, Event e, Parser p) {}

  /**
   * Apply matcher.
   *
   * @param input Input string.
   * @return True if matcher matches.
   */
  public Boolean matcher(String input) {
    return false;
  }

  private void setType(String value) {
    // Noop setter, required for event deserialization
  }

  /**
   * Get payload type.
   *
   * @return {@link Payload.PayloadType}
   */
  public Payload.PayloadType getType() {
    return null;
  }

  /**
   * Return a given String payload field value based on the supplied field identifier
   *
   * @param property {@link EventFilterPayload.StringProperty}
   * @return String value or null
   */
  public String eventStringValue(EventFilterPayload.StringProperty property) {
    return null;
  }
}
