package com.mozilla.secops.parser;

import java.io.Serializable;
import org.apache.beam.sdk.values.KV;

/**
 * Represents an event keyed with a particular string
 *
 * <p>This class is primarily used to encapsulate KV related functionality when returning keyed
 * events from ScriptRunner, avoiding the need for unchecked conversions due to type erasure.
 */
public class KeyedEvent implements Serializable {
  private static final long serialVersionUID = 1L;

  private final String key;
  private final Event event;

  /** Convert KeyedEvent to {@link KV} */
  public KV<String, Event> toKV() {
    if ((key == null) || (event == null)) {
      return null;
    }
    return KV.of(key, event);
  }

  /** Initialize new KeyedEvent */
  public KeyedEvent(String key, Event event) {
    this.key = key;
    this.event = event;
  }
}
