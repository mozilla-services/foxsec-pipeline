package com.mozilla.secops.parser;

import java.util.HashMap;
import java.util.Map;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.KV;

/**
 * Process an incoming raw event feed using multiple parser configurations
 *
 * <p>Similar to {@link ParserDoFn}, but can be used to process an incoming raw event feed that is
 * keyed using an identifier. An arbitrary number of parser configurations and filters can be
 * installed in the class associated with an identifier.
 *
 * <p>When the DoFn processes an incoming raw string, it will utilize the configuration and filters
 * associated with the identifier corresponding to the key of the input string.
 *
 * <p>The output will be the parsed event, keyed with the same identifier as the raw string.
 */
public class ParserMultiDoFn extends DoFn<KV<String, String>, KV<String, Event>> {
  private static final long serialVersionUID = 1L;

  private HashMap<String, ParserCfg> configurations;
  private HashMap<String, EventFilter> inlineFilters;
  private HashMap<String, EventFilter> commonInputFilters;

  private transient HashMap<String, Parser> parsers;

  /** Create new {@link ParserMultiDoFn} */
  public ParserMultiDoFn() {
    configurations = new HashMap<String, ParserCfg>();
    inlineFilters = new HashMap<String, EventFilter>();
    commonInputFilters = new HashMap<String, EventFilter>();
  }

  /**
   * Add a new parser configuration and filter for the specified key name
   *
   * @param name Identifier name
   * @param cfg Parser configuration
   * @param inlineFilter Inline event filter, null for none
   */
  public void addParser(String name, ParserCfg cfg, EventFilter inlineFilter) {
    if (cfg == null) {
      throw new IllegalArgumentException("new parser must have configuration");
    }
    configurations.put(name, cfg);
    if (inlineFilter != null) {
      inlineFilters.put(name, inlineFilter);
    }
  }

  @Setup
  public void setup() {
    parsers = new HashMap<String, Parser>();
    // Create an instance of the parser for each configuration we have
    for (Map.Entry<String, ParserCfg> entry : configurations.entrySet()) {
      ParserCfg c = entry.getValue();
      parsers.put(entry.getKey(), new Parser(c));

      // Install a common input filter for this parser instance if needed; see the comments in
      // ParserDoFn for more details on this
      if ((c.getStackdriverLabelFilters() != null) || (c.getStackdriverProjectFilter() != null)) {
        EventFilter commonInputFilter = new EventFilter().passConfigurationTicks();
        EventFilterRule rule = new EventFilterRule();

        if (c.getStackdriverLabelFilters() != null) {
          for (String labelFilter : c.getStackdriverLabelFilters()) {
            String parts[] = labelFilter.split(":");
            if (parts.length != 2) {
              throw new IllegalArgumentException(
                  "invalid format for Stackdriver label filter, must be <key>:<value>");
            }
            rule.wantStackdriverLabel(parts[0], parts[1]);
          }
        }

        if (c.getStackdriverProjectFilter() != null) {
          rule.wantStackdriverProject(c.getStackdriverProjectFilter());
        }

        commonInputFilter.addRule(rule);
        commonInputFilters.put(entry.getKey(), commonInputFilter);
      }
    }
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    KV<String, String> raw = c.element();

    Parser p = parsers.get(raw.getKey());
    if (p == null) {
      throw new RuntimeException(String.format("input for unknown element %s", raw.getKey()));
    }
    EventFilter common = commonInputFilters.get(raw.getKey());
    EventFilter inline = inlineFilters.get(raw.getKey());
    ParserCfg cfg = configurations.get(raw.getKey());

    Event e = p.parse(raw.getValue());
    if (e == null) {
      return;
    }

    if (common != null) {
      if (!(common.matches(e))) {
        return;
      }
    }

    if (inline != null) {
      if (!(inline.matches(e))) {
        return;
      }
    }

    if (cfg.getUseEventTimestamp()) {
      c.outputWithTimestamp(KV.of(raw.getKey(), e), e.getTimestamp().toInstant());
    } else {
      c.output(KV.of(raw.getKey(), e));
    }
  }
}
