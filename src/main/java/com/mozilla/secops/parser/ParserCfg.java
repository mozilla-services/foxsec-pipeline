package com.mozilla.secops.parser;

import com.mozilla.secops.InputOptions;
import java.io.Serializable;

/** Represents configuration data used to configure an instance of a {@link Parser} */
public class ParserCfg implements Serializable {
  private static final long serialVersionUID = 1L;

  private String maxmindDbPath;
  private Integer httpMultiAddressSelector;

  /**
   * Create a parser configuration from pipeline {@link InputOptions}
   *
   * @param options Input options
   * @return Parser configuration
   */
  public static ParserCfg fromInputOptions(InputOptions options) {
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindDbPath(options.getMaxmindDbPath());
    cfg.setHttpMultiAddressSelector(options.getHttpMultiAddressSelector());
    return cfg;
  }

  /**
   * Get HTTP multi-address selector value
   *
   * <p>The multi-address field if set is used to inform the parser which address is to be used as
   * the client source address in cases where a parsed HTTP request has multiple source IP addresses
   * (for example, an XFF chain).
   *
   * <p>The value should be <= -1, or >= 1. -1 indicates the rightmost address in the list. -2 the
   * second rightmost, etc. 1 indicates the first address in the list, 2 the second, etc.
   *
   * @return Integer or null if not specified
   */
  public Integer getHttpMultiAddressSelector() {
    return httpMultiAddressSelector;
  }

  /**
   * Set HTTP multi-address selector value
   *
   * @param value Field selector
   */
  public void setHttpMultiAddressSelector(Integer value) {
    httpMultiAddressSelector = value;
  }

  /**
   * Get Maxmind database path
   *
   * @return String of null if not specified
   */
  public String getMaxmindDbPath() {
    return maxmindDbPath;
  }

  /**
   * Set Maxmind database path
   *
   * @param path Path
   */
  public void setMaxmindDbPath(String path) {
    maxmindDbPath = path;
  }

  /** Construct default parser configuration */
  public ParserCfg() {}
}
