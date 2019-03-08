package com.mozilla.secops.parser;

import java.util.ArrayList;

/** Interface representing a payload filter */
public interface EventFilterPayloadInterface {
  /**
   * Should return true if the filter matches the supplied event
   *
   * @param e Event
   * @return Boolean
   */
  public Boolean matches(Event e);

  /**
   * Return extracted keys from event based on string selectors
   *
   * @param e Input event
   * @return {@link ArrayList} of extracted keys
   */
  public ArrayList<String> getKeys(Event e);
}
