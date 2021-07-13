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
  private Integer maxTimestampDifference;

  private Boolean disableCloudwatchStrip;
  private Boolean disableMozlogStrip;

  private String stackdriverProjectFilter;
  private String[] stackdriverLabelFilters;

  private Boolean deferGeoIpResolution;
  private Boolean useProxyXff;
  private Boolean xffAsRemote;

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
    cfg.setDeferGeoIpResolution(options.getDeferGeoIpResolution());
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
    cfg.setMaxTimestampDifference(options.getMaxAllowableTimestampDifference());
    cfg.setDisableMozlogStrip(options.getDisableMozlogStrip());
    cfg.setDisableCloudwatchStrip(options.getDisableCloudwatchStrip());
    cfg.setUseProxyXff(options.getUseProxyXff());
    cfg.setUseXffAsRemote(options.getUseXffAsRemote());
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
   *
   * @param subnets Arraylist containing subnets
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
    disableCloudwatchStrip = false;
    disableMozlogStrip = false;
    deferGeoIpResolution = false;
    useProxyXff = false;
    xffAsRemote = false;
  }

  /**
   * Set disable Cloudwatch strip
   *
   * <p>If it is known ahead of time the parser will never have to strip cloudwatch encapsulation
   * off an event, this flag can be enabled which will increase parser performance.
   *
   * @param disableCloudwatchStrip Boolean
   */
  @JsonProperty("disable_cloudwatch_strip")
  public void setDisableCloudwatchStrip(boolean disableCloudwatchStrip) {
    this.disableCloudwatchStrip = disableCloudwatchStrip;
  }

  /**
   * Get disable Cloudwatch strip flag
   *
   * @return Boolean
   */
  public Boolean getDisableCloudwatchStrip() {
    return disableCloudwatchStrip;
  }

  /**
   * Set disable Mozlog strip
   *
   * <p>If it is known ahead of time the parser will never have to strip mozlog encapsulation off an
   * event, this flag can be enabled which will increase parser performance.
   *
   * @param disableMozlogStrip Boolean
   */
  @JsonProperty("disable_mozlog_strip")
  public void setDisableMozlogStrip(boolean disableMozlogStrip) {
    this.disableMozlogStrip = disableMozlogStrip;
  }

  /**
   * Get disable Mozlog strip flag
   *
   * @return Boolean
   */
  public Boolean getDisableMozlogStrip() {
    return disableMozlogStrip;
  }

  /**
   * Set maximum allowable timestamp difference
   *
   * <p>If set, events which are parsed will have the timestamp included with the event compared
   * against the current time. If the difference exceeds the specified value in seconds, the event
   * will be dropped.
   *
   * <p>By default, this value is not set. Note that not all payload parsers will extract and set an
   * event timestamp. In cases where this does not happen, the event timestamp will just default to
   * the time the event was parsed (current time).
   *
   * @param maxTimestampDifference Max timestamp difference in seconds
   */
  public void setMaxTimestampDifference(Integer maxTimestampDifference) {
    this.maxTimestampDifference = maxTimestampDifference;
  }

  /**
   * Get maximum allowable timestamp difference
   *
   * @return Difference in seconds, or null if unset
   */
  public Integer getMaxTimestampDifference() {
    return maxTimestampDifference;
  }

  /**
   * Set defer GeoIP resolution
   *
   * <p>If set, GeoIP resolution on events will not actually occur until a GeoIP related field is
   * read. Otherwise, it will occur immediately when a source address field is set if GeoIP is
   * enabled.
   *
   * @param deferGeoIpResolution Boolean
   */
  @JsonProperty("defer_geoip_resolution")
  public void setDeferGeoIpResolution(Boolean deferGeoIpResolution) {
    this.deferGeoIpResolution = deferGeoIpResolution;
  }

  /**
   * Get defer GeoIP resolution setting
   *
   * @return Boolean
   */
  public Boolean getDeferGeoIpResolution() {
    return deferGeoIpResolution;
  }

  /**
   * Set enable proxy xff
   *
   * <p>If set, preprocesses the remote addr chain based on proxy header presence.
   *
   * @param useProxyXff Boolean
   */
  @JsonProperty("use_proxy_xff")
  public void setUseProxyXff(Boolean useProxyXff) {
    this.useProxyXff = useProxyXff;
  }

  /**
   * Get whether to use the proxy header to select ip from XFF
   *
   * @return whether the proxy xff setting is enabled
   */
  public Boolean getUseProxyXff() {
    return useProxyXff;
  }

  /**
   * Parse the X-Forwarded-For header instead of the remote addr
   *
   * <p>If set, parse XFF header, if present, in supported message types and enable usage of the XFF
   * header. This is explicitly enabled to support inconsistent log formats where multiple IPs may
   * also be used in remote addr fields.
   *
   * @param xffAsRemote Boolean
   */
  @JsonProperty("xff_as_remote")
  public void setUseXffAsRemote(Boolean xffAsRemote) {
    this.xffAsRemote = xffAsRemote;
  }

  /**
   * Get Use Xff Header as Remote
   *
   * @return whether an XFF header value overrides remote ip value for supported event types
   */
  public Boolean getUseXffAsRemote() {
    return xffAsRemote;
  }
}
