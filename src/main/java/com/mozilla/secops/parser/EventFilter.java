package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;

/** Event filtering and matching */
public class EventFilter implements Serializable {
  private static final long serialVersionUID = 1L;

  private ArrayList<EventFilterRule> rules;

  private Boolean wantUTC;
  private Boolean matchAny; // If true, match on any input event

  /**
   * Configure filter to pass configuration ticks
   *
   * <p>Adds a rule to the filter that will pass configuration ticks.
   *
   * @return EventFilter
   */
  public EventFilter passConfigurationTicks() {
    addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.CFGTICK));
    return this;
  }

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
                      c.output(e);
                    }
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
   * Add new rule to filter
   *
   * @param rule New rule to add
   */
  public void addRule(EventFilterRule rule) {
    rules.add(rule);
  }

  /**
   * Set filter rules
   *
   * @param rules Array of rules
   */
  @JsonProperty("rules")
  public void setRules(ArrayList<EventFilterRule> rules) {
    this.rules = rules;
  }

  /**
   * Get configured rules
   *
   * @return Array of rules
   */
  public ArrayList<EventFilterRule> getRules() {
    return rules;
  }

  /**
   * Choose to ignore non-UTC timezone events
   *
   * @param flag If true, drop events with parsed timezones that are not UTC
   * @return EventFilter for chaining
   */
  @JsonProperty("want_utc")
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

  /**
   * Set match any flag to specified value
   *
   * @param matchAny True to match everything
   */
  @JsonProperty("match_any")
  public void setMatchAny(Boolean matchAny) {
    this.matchAny = matchAny;
  }

  /**
   * Get match any setting
   *
   * @return Boolean
   */
  public Boolean getMatchAny() {
    return matchAny;
  }

  /** Create new {@link EventFilter} */
  public EventFilter() {
    rules = new ArrayList<EventFilterRule>();
    wantUTC = false;
    matchAny = false;
  }
}
