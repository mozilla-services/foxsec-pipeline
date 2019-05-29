package com.mozilla.secops.customs;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/** Maps to a customs pipeline configuration file */
public class CustomsCfg implements Serializable {
  private static final long serialVersionUID = 1L;

  private Map<String, CustomsCfgEntry> detectors;

  /**
   * Load customs configuration from a resource path
   *
   * @param resourcePath Path to resource
   * @return Customs configuration
   */
  public static CustomsCfg loadFromResource(String resourcePath) throws IOException {
    InputStream in = CustomsCfg.class.getResourceAsStream(resourcePath);
    if (in == null) {
      throw new IOException("customs configuration resource not found");
    }
    ObjectMapper mapper = new ObjectMapper();
    return mapper.readValue(in, CustomsCfg.class).validate();
  }

  /**
   * Ensure configuration is valid
   *
   * @return Configuration, throws exception if inconsistencies identified
   */
  public CustomsCfg validate() throws IOException {
    if (detectors.size() == 0) {
      throw new IOException("no detectors configured");
    }
    for (CustomsCfgEntry entry : detectors.values()) {
      entry.validate();
    }
    return this;
  }

  /**
   * Get all configured detectors
   *
   * @return Map where key is detector name and value is detector configuration
   */
  @JsonProperty("detectors")
  public Map<String, CustomsCfgEntry> getDetectors() {
    return detectors;
  }

  public CustomsCfg() {
    detectors = new HashMap<String, CustomsCfgEntry>();
  }
}
