package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.net.InetAddresses;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

/** CIDR matching utilities */
public class CidrUtil {
  private final String AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json";
  private final String GCP_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json";

  private ArrayList<IpAddressMatcher> subnets;
  private InetRadix inetTree;

  /** Load exclusion list from path resource */
  public static final int CIDRUTIL_FILE = 1;
  /** Load exclusion list with allowed cloud providers */
  public static final int CIDRUTIL_CLOUDPROVIDERS = 1 << 1;
  /** Load exclusion list for internal/RFC1918 subnets */
  public static final int CIDRUTIL_INTERNAL = 1 << 2;

  /** Constructor for {@link CidrUtil}, initialize empty */
  public CidrUtil() {
    subnets = new ArrayList<IpAddressMatcher>();
    inetTree = new InetRadix();
  }

  /**
   * Constructor for {@link CidrUtil} to load subnet list from resource
   *
   * @param path Resource path or GCS URL to load CIDR subnet list from
   * @throws IOException IOException
   */
  public CidrUtil(String path) throws IOException {
    this();
    ArrayList<String> flist = FileUtil.fileReadLines(path);
    for (String i : flist) {
      add(i);
    }
  }

  /**
   * Reverse DNS query of provided IP and comparison of result against pattern
   *
   * <p>A reverse DNS query for the supplied IP address is performed and the resulting hostname is
   * compared against the regular expression in pattern. If it matches, the function returns true
   * otherwise false.
   *
   * <p>This function attempts to also perform a forward DNS query on the hostname returned by the
   * reverse DNS query and ensures the IP address matches what was supplied as a function argument.
   *
   * @param ip IP address
   * @param pattern Regular expression to match against
   * @return True if hostname matches pattern, false otherwise
   */
  public static Boolean resolvedCanonicalHostMatches(String ip, String pattern) {
    Pattern p = Pattern.compile(pattern);

    InetAddress addr;
    try {
      addr = InetAddress.getByName(ip);
    } catch (UnknownHostException exc) {
      return false;
    }
    String hn = addr.getCanonicalHostName();
    if (hn.equals(ip)) {
      // If the returned value is the original address, the lookup operation could not be
      // completed, so just return false.
      return false;
    }

    InetAddress[] rlist;
    try {
      rlist = InetAddress.getAllByName(hn);
    } catch (UnknownHostException exc) {
      return false;
    }

    for (InetAddress r : rlist) {
      if (r.equals(addr)) {
        if (p.matcher(hn).matches()) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Returns a DoFn that filters any events that have a normalized source address field that matches
   * the specified criteria.
   *
   * <p>The flags parameter is a bitmask used to control the input criteria used in the filtering
   * operation.
   *
   * <p>{@value #CIDRUTIL_FILE} can be specified in the flags mask to indicate subnets should be
   * loaded from the specified path and any matching addresses should be filtered. If this bit is
   * included path must be non-null.
   *
   * <p>{@value #CIDRUTIL_CLOUDPROVIDERS} can be specified to load known cloud provider public
   * address ranges into the filter for exclusion.
   *
   * <p>{@value #CIDRUTIL_INTERNAL} can be specified to load internal (e.g., RFC1918) subnets into
   * the filter.
   *
   * @param flags Option bitmask
   * @param path Resource path or GCS URL to load subnets from for {@value #CIDRUTIL_FILE}
   * @return {@link DoFn}
   */
  public static DoFn<Event, Event> excludeNormalizedSourceAddresses(int flags, String path) {
    return new DoFn<Event, Event>() {
      private static final long serialVersionUID = 1L;

      private final String resourcePath;
      private final Boolean addCp;
      private final Boolean addInternal;
      private CidrUtil cidrs;

      {
        if ((flags & CIDRUTIL_FILE) == CIDRUTIL_FILE) {
          resourcePath = path;
        } else {
          resourcePath = null;
        }
        if ((flags & CIDRUTIL_CLOUDPROVIDERS) == CIDRUTIL_CLOUDPROVIDERS) {
          addCp = true;
        } else {
          addCp = false;
        }
        if ((flags & CIDRUTIL_INTERNAL) == CIDRUTIL_INTERNAL) {
          addInternal = true;
        } else {
          addInternal = false;
        }
      }

      @Setup
      public void setup() throws IOException {
        if (resourcePath != null) {
          cidrs = new CidrUtil(resourcePath);
        } else {
          cidrs = new CidrUtil();
        }
        if (addCp) {
          cidrs.loadGcpSubnets();
          cidrs.loadAwsSubnets();
        }
        if (addInternal) {
          cidrs.loadInternalSubnets();
        }
      }

      @ProcessElement
      public void processElement(ProcessContext c) {
        Event e = c.element();
        Normalized n = e.getNormalized();
        if (n != null) {
          String sourceAddress = n.getSourceAddress();
          if (sourceAddress != null) {
            if (cidrs.contains(sourceAddress)) {
              return;
            }
          }
        }
        c.output(e);
      }
    };
  }

  /**
   * Return true if address is within the cidr
   *
   * @param addr IP address to check against cidr
   * @param cidr cidr to check if it contains the IP address
   * @return True if addr is within the cidr.
   */
  public static boolean addressInCidr(String addr, String cidr) {
    IpAddressMatcher c = new IpAddressMatcher(cidr);
    return c.matches(addr);
  }

  /**
   * Determine if an address is an IPv4 address
   *
   * @param addr Address
   * @return boolean
   */
  public static boolean isInet4(String addr) {
    return InetAddresses.forString(addr).getAddress().length == 4 ? true : false;
  }

  /**
   * Strip the mask component from a CIDR subnet.
   *
   * <p>For example, given 192.168.0.0/24 return 192.168.0.0.
   *
   * @param cidr CIDR subnet
   * @return String
   */
  public static String stripMaskFromCidr(String cidr) {
    int i = cidr.indexOf("/");
    if (i == -1) {
      return null;
    }
    return cidr.substring(0, i);
  }

  /**
   * Return true if any loaded subnet contains the specified address
   *
   * @param addr IP address to check against subnets
   * @return True if any loaded subnet contains the address
   */
  public Boolean contains(String addr) {
    if (isInet4(addr)) {
      if (inetTree.contains(addr)) {
        return true;
      }
    } else {
      for (IpAddressMatcher s : subnets) {
        if (s.matches(addr)) {
          return true;
        }
      }
    }
    return false;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class GcpCidrPrefixEntry {
    String ip4Prefix;
    String ip6Prefix;
    String scope;
    String service;

    public String getIpPrefix() {
      if (getIp4Prefix() != null) {
        return getIp4Prefix();
      }
      return getIp6Prefix();
    }

    @JsonProperty("ipv4Prefix")
    public String getIp4Prefix() {
      return ip4Prefix;
    }

    @JsonProperty("ipv6Prefix")
    public String getIp6Prefix() {
      return ip6Prefix;
    }

    @JsonProperty("scope")
    public String getScope() {
      return scope;
    }

    @JsonProperty("service")
    public String getService() {
      return service;
    }
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class GcpCidrResponse {
    GcpCidrPrefixEntry[] ipPrefixes;

    @JsonProperty("prefixes")
    public GcpCidrPrefixEntry[] getIpPrefixes() {
      return ipPrefixes;
    }
  }

  /**
   * Load known GCP subnets into instance of {@link CidrUtil}
   *
   * <p>This is done using https://www.gstatic.com/ipranges/cloud.json as recommended by
   * https://cloud.google.com/compute/docs/faq#find_ip_range
   *
   * @throws IOException IOException
   */
  public void loadGcpSubnets() throws IOException {
    HttpClient httpClient = HttpClientBuilder.create().build();
    HttpGet get = new HttpGet(GCP_IP_RANGES_URL);
    HttpResponse resp = httpClient.execute(get);
    if (resp.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
      throw new IOException(
          String.format(
              "request failed with status code %d", resp.getStatusLine().getStatusCode()));
    }
    ObjectMapper mapper = new ObjectMapper();
    GcpCidrResponse gcpcidrs =
        mapper.readValue(resp.getEntity().getContent(), GcpCidrResponse.class);
    for (GcpCidrPrefixEntry e : gcpcidrs.getIpPrefixes()) {
      add(e.getIpPrefix());
    }
  }

  /** Populate CidrUtil instance with internal/RFC1918 subnets */
  public void loadInternalSubnets() {
    add("10.0.0.0/8");
    add("192.168.0.0/16");
    add("172.16.0.0/12");
    add("127.0.0.1/32");
    add("::1/128");
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class AwsCidrPrefixEntry {
    String ip4Prefix;
    String ip6Prefix;
    String region;
    String service;

    @JsonProperty("ip_prefix")
    public String getIp4Prefix() {
      return ip4Prefix;
    }

    @JsonProperty("ipv6_prefix")
    public String getIp6Prefix() {
      return ip6Prefix;
    }

    @JsonProperty("region")
    public String getRegion() {
      return region;
    }

    @JsonProperty("service")
    public String getService() {
      return service;
    }
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class AwsCidrResponse {
    AwsCidrPrefixEntry[] ip4Prefixes;
    AwsCidrPrefixEntry[] ip6Prefixes;

    @JsonProperty("prefixes")
    public AwsCidrPrefixEntry[] getIp4Prefixes() {
      return ip4Prefixes;
    }

    @JsonProperty("ipv6_prefixes")
    public AwsCidrPrefixEntry[] getIp6Prefixes() {
      return ip6Prefixes;
    }
  }

  /**
   * Load known AWS subnets into instance of {@link CidrUtil}
   *
   * <p>Utilizes information at https://ip-ranges.amazonaws.com/ip-ranges.json
   *
   * @throws IOException IOException
   */
  public void loadAwsSubnets() throws IOException {
    HttpClient httpClient = HttpClientBuilder.create().build();
    HttpGet get = new HttpGet(AWS_IP_RANGES_URL);
    HttpResponse resp = httpClient.execute(get);
    if (resp.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
      throw new IOException(
          String.format(
              "request failed with status code %d", resp.getStatusLine().getStatusCode()));
    }
    ObjectMapper mapper = new ObjectMapper();
    AwsCidrResponse awscidrs =
        mapper.readValue(resp.getEntity().getContent(), AwsCidrResponse.class);
    for (AwsCidrPrefixEntry e : awscidrs.getIp4Prefixes()) {
      add(e.getIp4Prefix());
    }
    for (AwsCidrPrefixEntry e : awscidrs.getIp6Prefixes()) {
      add(e.getIp6Prefix());
    }
  }

  /**
   * Add subnet to subnet list
   *
   * @param cidr Subnet to add
   */
  public void add(String cidr) {
    String addr = stripMaskFromCidr(cidr);
    if (addr == null) {
      throw new IllegalArgumentException(String.format("bad format, %s", cidr));
    }
    if (isInet4(addr)) {
      inetTree.add(cidr);
    } else {
      subnets.add(new IpAddressMatcher(cidr));
    }
  }
}
