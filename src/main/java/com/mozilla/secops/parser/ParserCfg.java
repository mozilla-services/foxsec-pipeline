package com.mozilla.secops.parser;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.InputOptions;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;

/** Represents configuration data used to configure an instance of a {@link Parser} */
public class ParserCfg implements Serializable {
  private static final long serialVersionUID = 1L;

  private String maxmindDbPath;
  private ArrayList<String> xffAddressSelectorSubnets;
  private String idmanagerPath;

  /**
   * Create a parser configuration from pipeline {@link InputOptions}
   *
   * @param options Input options
   * @return Parser configuration
   */
  public static ParserCfg fromInputOptions(InputOptions options) {
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindDbPath(options.getMaxmindDbPath());
    cfg.setIdentityManagerPath(options.getIdentityManagerPath());
    if (options.getXffAddressSelector() != null) {
      String parts[] = options.getXffAddressSelector().split(",");
      if (parts.length > 0) {
        cfg.setXffAddressSelector(new ArrayList<String>(Arrays.asList(parts)));
      }
    }
    return cfg;
  }

  /**
   * Set XFF address selectors
   *
   * <p>The subnets parameter should be an ArrayList containing CIDR subnets that will be used as
   * hints for selecting a real client IP address in the event parsers see an X-Forwarded-For style
   * address list.
   *
   * <p>If any address in the log entry address list matches a subnet in the configured selector
   * list, the address directly to the left will be used as the real client IP address.
   *
   * <p>If this value is not set, the rightmost address will always be used as the actual client IP
   * address.
   *
   * <p>This option is intended to behave in a similar manner to the nginx realip module,
   * https://nginx.org/en/docs/http/ngx_http_realip_module.html.
   */
  public void setXffAddressSelector(ArrayList<String> subnets) {
    xffAddressSelectorSubnets = subnets;
  }

  /**
   * Get any configured XFF address selectors
   *
   * @return {@link ArrayList} of subnets, or null if unset
   */
  public ArrayList<String> getXffAddressSelector() {
    return xffAddressSelectorSubnets;
  }

  /**
   * Return any configured XFF address selectors as a {@link CidrUtil} object.
   *
   * @return CidrUtil or null if not set
   */
  public CidrUtil getXffAddressSelectorAsCidrUtil() {
    if (xffAddressSelectorSubnets == null) {
      return null;
    }
    CidrUtil ret = new CidrUtil();
    for (String s : xffAddressSelectorSubnets) {
      ret.add(s);
    }
    return ret;
  }

  /**
   * Get Maxmind database path
   *
   * @return String or null if not specified
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

  /**
   * Get IdentityManager json file path
   *
   * @return String of null if not specified
   */
  public String getIdentityManagerPath() {
    return idmanagerPath;
  }

  /**
   * Set IdentityManager json file path
   *
   * @param path Path
   */
  public void setIdentityManagerPath(String path) {
    idmanagerPath = path;
  }

  /** Construct default parser configuration */
  public ParserCfg() {}
}
