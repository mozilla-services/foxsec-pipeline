package com.mozilla.secops.parser;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.InputOptions;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;

/** Represents configuration data used to configure an instance of a {@link Parser} */
@JsonInclude(Include.NON_EMPTY)
public class ParserCfg implements Serializable {
  private static final long serialVersionUID = 1L;

  private String maxmindCityDbPath;
  private String maxmindIspDbPath;
  private String fastMatcher;
  private ArrayList<String> xffAddressSelectorSubnets;
  private String idmanagerPath;
  private Boolean useEventTimestamp;

  private String stackdriverProjectFilter;
  private String[] stackdriverLabelFilters;

  /**
   * Create a parser configuration from pipeline {@link InputOptions}
   *
   * @param options Input options
   * @return Parser configuration
   */
  public static ParserCfg fromInputOptions(InputOptions options) {
    ParserCfg cfg = new ParserCfg();
    cfg.setUseEventTimestamp(options.getUseEventTimestamp());
    cfg.setMaxmindCityDbPath(options.getMaxmindCityDbPath());
    cfg.setMaxmindIspDbPath(options.getMaxmindIspDbPath());
    cfg.setIdentityManagerPath(options.getIdentityManagerPath());
    cfg.setParserFastMatcher(options.getParserFastMatcher());
    if (options.getXffAddressSelector() != null) {
      String parts[] = options.getXffAddressSelector().split(",");
      if (parts.length > 0) {
        cfg.setXffAddressSelector(new ArrayList<String>(Arrays.asList(parts)));
      }
    }
    cfg.setStackdriverProjectFilter(options.getStackdriverProjectFilter());
    cfg.setStackdriverLabelFilters(options.getStackdriverLabelFilters());
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
  @JsonProperty("xff_address_selector")
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
  @JsonIgnore
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
   * Get Maxmind City database path
   *
   * @return String or null if not specified
   */
  public String getMaxmindCityDbPath() {
    return maxmindCityDbPath;
  }

  /**
   * Set Maxmind City database path
   *
   * @param path Path
   */
  @JsonProperty("maxmind_city_db_path")
  public void setMaxmindCityDbPath(String path) {
    maxmindCityDbPath = path;
  }

  /**
   * Get Maxmind ISP database path
   *
   * @return String or null if not specified
   */
  public String getMaxmindIspDbPath() {
    return maxmindIspDbPath;
  }

  /**
   * Set Maxmind ISP database path
   *
   * @param path Path
   */
  @JsonProperty("maxmind_isp_db_path")
  public void setMaxmindIspDbPath(String path) {
    maxmindIspDbPath = path;
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
  @JsonProperty("identity_manager_path")
  public void setIdentityManagerPath(String path) {
    idmanagerPath = path;
  }

  /*
   * Get parser fast matcher
   *
   * @return String or null if not specified
   */
  public String getParserFastMatcher() {
    return fastMatcher;
  }

  /**
   * Set parser fast matcher
   *
   * <p>If a fast matcher is set in the parser, an input string is immediately tested to see if it
   * contains the supplied substring. If not, the event is dropped prior to performing the bulk of
   * the parsing/filtering operations.
   *
   * <p>Note that this is intended to reduce pressure on the parser and should not be treated as a
   * filter, as there are certain cases (such as with configuration tick events) that messages that
   * do not match the fast matcher will still be returned.
   *
   * @param fastMatcher Matcher substring
   */
  @JsonProperty("parser_fast_matcher")
  public void setParserFastMatcher(String fastMatcher) {
    this.fastMatcher = fastMatcher;
  }

  /**
   * Get event timestamp emission setting
   *
   * @return Boolean
   */
  public Boolean getUseEventTimestamp() {
    return useEventTimestamp;
  }

  /**
   * Set event timestamp emission setting
   *
   * <p>This option is only applicable when the parser is being used within {@link ParserDoFn}.
   *
   * <p>If true, events will be output in the pipeline using the timestamp within the event rather
   * than the default timestamp that would be assigned.
   *
   * @param useEventTimestamp Boolean
   */
  @JsonProperty("use_event_timestamp")
  public void setUseEventTimestamp(Boolean useEventTimestamp) {
    this.useEventTimestamp = useEventTimestamp;
  }

  /**
   * Get Stackdriver label filters
   *
   * @return Array of key:value labels that must match
   */
  public String[] getStackdriverLabelFilters() {
    return stackdriverLabelFilters;
  }

  /**
   * Set Stackdriver label filters
   *
   * <p>This option is only applicable when the parser is being used within {@link ParserDoFn}.
   *
   * <p>If set, events that do not match the label specification will be dropped.
   *
   * @param stackdriverLabelFilters Array of key:value labels that must match
   */
  @JsonProperty("stackdriver_label_filters")
  public void setStackdriverLabelFilters(String[] stackdriverLabelFilters) {
    this.stackdriverLabelFilters = stackdriverLabelFilters;
  }

  /**
   * Get Stackdriver project filter
   *
   * @return Project filter value
   */
  public String getStackdriverProjectFilter() {
    return stackdriverProjectFilter;
  }

  /**
   * Set Stackdriver project filter
   *
   * <p>This option is only applicable when the parser is being used within {@link ParserDoFn}
   *
   * <p>If set, events that do not have the specified Stackdriver project value will be dropped.
   *
   * @param stackdriverProjectFilter Project value
   */
  @JsonProperty("stackdriver_project_filter")
  public void setStackdriverProjectFilter(String stackdriverProjectFilter) {
    this.stackdriverProjectFilter = stackdriverProjectFilter;
  }

  /** Construct default parser configuration */
  public ParserCfg() {
    useEventTimestamp = false;
  }
}
