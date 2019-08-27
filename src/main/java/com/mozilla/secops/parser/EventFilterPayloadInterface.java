package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/** Interface representing a payload filter */
@JsonDeserialize(using = EventFilterPayloadDeserializer.class)
public interface EventFilterPayloadInterface {
  /**
   * Should return true if the filter matches the supplied event
   *
   * @param e Event
   * @return Boolean
   */
  public Boolean matches(Event e);
}
