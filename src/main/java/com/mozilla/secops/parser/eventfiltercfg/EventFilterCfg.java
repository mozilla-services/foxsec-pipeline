package com.mozilla.secops.parser.eventfiltercfg;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.PayloadBase;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

class FilterRulePayloadFilter {
  private String wantClass;
  private ArrayList<ArrayList<String>> stringMatches;
  private ArrayList<String> stringSelectors;

  /** Validate configuration of payload filter */
  public void validate() throws IOException {}

  @JsonProperty("class")
  public String getWantClass() {
    return wantClass;
  }

  @JsonProperty("string_match")
  public ArrayList<ArrayList<String>> getStringMatches() {
    return stringMatches;
  }

  @JsonProperty("string_selectors")
  public ArrayList<String> getStringSelectors() {
    return stringSelectors;
  }

  FilterRulePayloadFilter() {
    stringMatches = new ArrayList<ArrayList<String>>();
    stringSelectors = new ArrayList<String>();
  }
}

class FilterRule {
  private String wantSubtype;
  private ArrayList<FilterRulePayloadFilter> payloadFilters;

  /** Validate configuration of filter rule */
  public void validate() throws IOException {
    for (FilterRulePayloadFilter frpf : payloadFilters) {
      frpf.validate();
    }
  }

  @JsonProperty("subtype")
  public String getWantSubtype() {
    return wantSubtype;
  }

  @JsonProperty("payload_filters")
  public ArrayList<FilterRulePayloadFilter> getPayloadFilters() {
    return payloadFilters;
  }

  FilterRule() {
    payloadFilters = new ArrayList<FilterRulePayloadFilter>();
  }
}

class FilterCfg {
  private ArrayList<FilterRule> filterRules;
  private ArrayList<FilterRule> keyingRules;
  private Boolean outputWithTimestamp;

  @JsonProperty("rules")
  public ArrayList<FilterRule> getFilterRules() {
    return filterRules;
  }

  @JsonProperty("keying")
  public ArrayList<FilterRule> getKeyingRules() {
    return keyingRules;
  }

  @JsonProperty("output_with_timestamp")
  public Boolean getOutputWithTimestamp() {
    return outputWithTimestamp;
  }

  /** Validate filter configuration */
  public void validate() throws IOException {
    for (FilterRule rule : filterRules) {
      rule.validate();
    }
    for (FilterRule rule : keyingRules) {
      rule.validate();
    }
  }

  FilterCfg() {
    outputWithTimestamp = false;
    filterRules = new ArrayList<FilterRule>();
    keyingRules = new ArrayList<FilterRule>();
  }
}

/**
 * Initialize {@link EventFilter} objects using a configuration file
 *
 * <p>The {@link EventFilterCfg} class supports initializing event filters using filter
 * configuration that is specified in a JSON configuration file rather then calling into the
 * filtering API directly. This is useful for supporting more dynamic filter configuration without
 * code changes.
 */
public class EventFilterCfg {
  private Map<String, FilterCfg> filterCfgs;
  private Boolean timestampOverride;

  /**
   * Return filter configuration loaded from the configuration file, where the key is the name of
   * the filter.
   *
   * @return Map of filter name / filter configuration
   */
  @JsonProperty("filters")
  public Map<String, FilterCfg> getFilters() {
    return filterCfgs;
  }

  /** Validate filter configuration */
  public void validate() throws IOException {
    for (FilterCfg cfg : filterCfgs.values()) {
      cfg.validate();
    }
  }

  /**
   * Set to manually override timestamp emission setting in filter configuration
   *
   * @param flag True to emit with timestamps, false to disable
   */
  public void setTimestampOverride(Boolean flag) {
    timestampOverride = flag;
  }

  @SuppressWarnings("unchecked")
  private EventFilterRule processRuleConfiguration(FilterRule rule) throws IOException {
    EventFilterRule newRule = new EventFilterRule();
    if (rule.getWantSubtype() != null) {
      newRule.wantSubtype(Payload.PayloadType.valueOf(rule.getWantSubtype()));
    }

    for (FilterRulePayloadFilter pFilter : rule.getPayloadFilters()) {
      EventFilterPayload p;
      if (pFilter.getWantClass() != null) {
        Class<?> cls;
        try {
          cls = Class.forName(pFilter.getWantClass());
        } catch (ClassNotFoundException exc) {
          throw new IOException("invalid want class specification in payload filter");
        }
        if (!(PayloadBase.class.isAssignableFrom(cls))) {
          throw new IOException("class specification in payload filter is not a payload class");
        }
        p = new EventFilterPayload((Class<? extends PayloadBase>) cls);
      } else {
        p = new EventFilterPayload();
      }

      for (ArrayList<String> element : pFilter.getStringMatches()) {
        if (element.size() != 2) {
          throw new IOException("invalid string match configuration");
        }
        p.withStringMatch(
            EventFilterPayload.StringProperty.valueOf(element.get(0)), element.get(1));
      }

      for (String element : pFilter.getStringSelectors()) {
        p.withStringSelector(EventFilterPayload.StringProperty.valueOf(element));
      }
      newRule.addPayloadFilter(p);
    }
    return newRule;
  }

  /**
   * Given a filter name from the filter configuration, return an initialized {@link EventFilter}
   * object
   *
   * @param filterName Filter name from configuration file
   * @return Initialized {@link EventFilter}, null if filter was not found
   */
  public EventFilter getEventFilter(String filterName) throws IOException {
    FilterCfg cfg = getFilters().get(filterName);
    if (cfg == null) {
      return null;
    }

    EventFilter ret;
    if (timestampOverride == null) {
      ret = new EventFilter().setOutputWithTimestamp(cfg.getOutputWithTimestamp());
    } else {
      ret = new EventFilter().setOutputWithTimestamp(timestampOverride);
    }

    for (FilterRule rule : cfg.getFilterRules()) {
      ret.addRule(processRuleConfiguration(rule));
    }
    for (FilterRule rule : cfg.getKeyingRules()) {
      ret.addKeyingSelector(processRuleConfiguration(rule));
    }

    return ret;
  }

  /**
   * Load filter configuration from a resource file
   *
   * @param resourcePath Path to resource JSON file
   * @return EventFilterCfg
   */
  public static EventFilterCfg loadFromResource(String resourcePath) throws IOException {
    InputStream in = EventFilterCfg.class.getResourceAsStream(resourcePath);
    if (in == null) {
      throw new IOException("event filter configuration resource not found");
    }
    ObjectMapper mapper = new ObjectMapper();
    return mapper.readValue(in, EventFilterCfg.class);
  }

  /** Initialize new {@link EventFilterCfg} */
  public EventFilterCfg() {
    filterCfgs = new HashMap<String, FilterCfg>();
  }
}
