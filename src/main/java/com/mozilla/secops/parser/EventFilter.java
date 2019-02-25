package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Base64;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/** Event filtering and matching */
public class EventFilter implements Serializable {
  private static final long serialVersionUID = 1L;

  private ArrayList<EventFilterRule> rules;
  private ArrayList<EventFilterRule> keySelectors;

  private Boolean wantUTC;
  private Boolean outputWithTimestamp;
  private Boolean matchAny; // If true, match on any input event

  private static final String keyChar = " ";
  private static final String splitChar = "\\ ";

  /**
   * Get composite transform to apply filter to event stream
   *
   * @param filter Event filter
   * @return Transform
   */
  public static PTransform<PCollection<Event>, PCollection<Event>> getTransform(
      EventFilter filter) {
    return new PTransform<PCollection<Event>, PCollection<Event>>() {
      private static final long serialVersionUID = 1L;

      @Override
      public PCollection<Event> expand(PCollection<Event> input) {
        return input.apply(
            ParDo.of(
                new DoFn<Event, Event>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    Event e = c.element();
                    if (filter.matches(e)) {
                      if (filter.getOutputWithTimestamp()) {
                        c.outputWithTimestamp(e, e.getTimestamp().toInstant());
                      } else {
                        c.output(e);
                      }
                    }
                  }
                }));
      }
    };
  }

  /**
   * Get composite transform to apply filter to event stream and perform any required keying
   * operations
   *
   * @param filter Event filter
   * @return Transform
   */
  public static PTransform<PCollection<Event>, PCollection<KV<String, Event>>> getKeyingTransform(
      EventFilter filter) {
    return new PTransform<PCollection<Event>, PCollection<KV<String, Event>>>() {
      private static final long serialVersionUID = 1L;

      @Override
      public PCollection<KV<String, Event>> expand(PCollection<Event> input) {
        return input
            .apply(getTransform(filter))
            .apply(
                ParDo.of(
                    new DoFn<Event, KV<String, Event>>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        Event e = c.element();
                        String key = filter.getKey(e);
                        if (key == null) {
                          return;
                        }
                        c.output(KV.of(key, e));
                      }
                    }));
      }
    };
  }

  /**
   * Test if event matches filter
   *
   * @param e Event to match against filter
   * @return True if filter matches
   */
  public Boolean matches(Event e) {
    if (matchAny) {
      return true;
    }
    if (wantUTC) {
      if (!(e.getTimestamp().getZone().getID().equals("Etc/UTC")
          || e.getTimestamp().getZone().getID().equals("UTC"))) {
        return false;
      }
    }
    for (EventFilterRule r : rules) {
      if (r.matches(e)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Given any keySelectors return the applicable key from the event
   *
   * <p>Base64 encoding is applied to key sub elements that are used in the returned key.
   *
   * <p>Pipelines should use splitKey to convert the elements back to their original form.
   *
   * @param e Input event
   * @return Key string
   */
  public String getKey(Event e) {
    ArrayList<String> keys = new ArrayList<String>();
    for (EventFilterRule r : keySelectors) {
      ArrayList<String> values = r.getKeys(e);
      if (values == null) {
        return null;
      }
      keys.addAll(values);
    }
    return String.join(keyChar, keys);
  }

  /**
   * Given a key constructed using a keying transform, split it into it's individual elements.
   *
   * @param input Input string
   * @return Array of elements
   */
  public static String[] splitKey(String input) {
    String[] oe = input.split(splitChar);
    String[] ret = new String[oe.length];
    for (int i = 0; i < oe.length; i++) {
      ret[i] = new String(Base64.getDecoder().decode(oe[i].getBytes()));
    }
    return ret;
  }

  /**
   * Add new rule to filter
   *
   * @param rule New rule to add
   */
  public void addRule(EventFilterRule rule) {
    rules.add(rule);
  }

  /**
   * Add a new keying selector to the filter
   *
   * @param rule New rule to add that includes key selector
   */
  public void addKeyingSelector(EventFilterRule rule) {
    keySelectors.add(rule);
  }

  /**
   * Set timestamp handling for event output
   *
   * @param flag If true use event timestamp on output
   * @return EventFilter for chaining
   */
  public EventFilter setOutputWithTimestamp(Boolean flag) {
    outputWithTimestamp = flag;
    return this;
  }

  /**
   * Get timestamp handling for event output
   *
   * @return True if events should be emitted with timestamp
   */
  public Boolean getOutputWithTimestamp() {
    return outputWithTimestamp;
  }

  /**
   * Choose to ignore non-UTC timezone events
   *
   * @param flag If true, drop events with parsed timezones that are not UTC
   * @return EventFilter for chaining
   */
  public EventFilter setWantUTC(Boolean flag) {
    wantUTC = flag;
    return this;
  }

  /**
   * Get UTC handling parameter
   *
   * @return True if non-UTC events should be dropped in filter
   */
  public Boolean getWantUTC() {
    return wantUTC;
  }

  public EventFilter matchAny() {
    matchAny = true;
    return this;
  }

  /** Create new {@link EventFilter} */
  public EventFilter() {
    rules = new ArrayList<EventFilterRule>();
    keySelectors = new ArrayList<EventFilterRule>();
    wantUTC = false;
    matchAny = false;
    outputWithTimestamp = false;
  }
}
