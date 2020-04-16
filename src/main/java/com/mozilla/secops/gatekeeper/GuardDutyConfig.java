package com.mozilla.secops.gatekeeper;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.FileUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link GuardDutyConfig} is used for configuring our use of Guardduty, i.e. which Finding's to
 * ignore / escalate
 */
public class GuardDutyConfig implements Serializable {
  private static final long serialVersionUID = 1L;

  private List<GuardDutyFindingMatcher> ignoreMatchers;
  private List<GuardDutyFindingMatcher> highSeverityMatchers;

  /**
   * Load guardduty configuration from a resource file
   *
   * @param path Path to load JSON file from, resource path or GCS URL
   * @return {@link GuardDutyConfig}
   * @throws IOException IOException
   */
  public static GuardDutyConfig load(String path) throws IOException {
    InputStream in = FileUtil.getStreamFromPath(path);
    ObjectMapper mapper = new ObjectMapper();
    return mapper.readValue(in, GuardDutyConfig.class);
  }

  /**
   * Get ignore finding matchers
   *
   * @return {@link List} of {@link GuardDutyFindingMatcher}
   */
  @JsonProperty("ignore_matchers")
  public List<GuardDutyFindingMatcher> getIgnoreMatchers() {
    return ignoreMatchers;
  }

  /**
   * Get high severity finding matchers
   *
   * @return {@link List} of {@link GuardDutyFindingMatcher}
   */
  @JsonProperty("high_severity_matchers")
  public List<GuardDutyFindingMatcher> getHighSeverityMatchers() {
    return highSeverityMatchers;
  }

  /** Create a new empty GuardDutyConfig */
  public GuardDutyConfig() {
    ignoreMatchers = new ArrayList<GuardDutyFindingMatcher>();
    highSeverityMatchers = new ArrayList<GuardDutyFindingMatcher>();
  }
}
