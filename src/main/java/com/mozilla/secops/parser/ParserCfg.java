package com.mozilla.secops.parser;

import com.mozilla.secops.InputOptions;
import java.io.Serializable;

/** Represents configuration data used to configure an instance of a {@link Parser} */
public class ParserCfg implements Serializable {
  private static final long serialVersionUID = 1L;

  private String maxmindDbPath;

  public static ParserCfg fromInputOptions(InputOptions options) {
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindDbPath(options.getMaxmindDbPath());
    return cfg;
  }

  /**
   * Get Maxmind database path
   *
   * @return String
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
