package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.regex.Pattern;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
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

  private ArrayList<IpAddressMatcher> subnets;

  /** Load exclusion list from path resource */
  public static final int CIDRUTIL_FILE = 1;
  /** Load exclusion list with whitelisted cloud providers */
  public static final int CIDRUTIL_CLOUDPROVIDERS = 1 << 1;
  /** Load exclusion list for internal/RFC1918 subnets */
  public static final int CIDRUTIL_INTERNAL = 1 << 2;

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
   * Return true if any loaded subnet contains the specified address
   *
   * @param addr IP address to check against subnets
   * @return True if any loaded subnet contains the address
   */
  public Boolean contains(String addr) {
    for (IpAddressMatcher s : subnets) {
      if (s.matches(addr)) {
        return true;
      }
    }
    return false;
  }

  private static ArrayList<String> spfResolver(String record, String prefix) {
    ArrayList<String> ret = new ArrayList<>();
    try {
      Attributes attrs =
          new InitialDirContext().getAttributes("dns:" + record, new String[] {"TXT"});
      NamingEnumeration<? extends Attribute> spfdom = attrs.getAll();
      while (spfdom.hasMore()) {
        Attribute a = spfdom.next();
        Enumeration<?> v = a.getAll();
        while (v.hasMoreElements()) {
          String x = v.nextElement().toString();
          String[] parts = x.split(" ");
          for (String p : parts) {
            if (p.matches("^" + prefix + ".*")) {
              ret.add(p.replaceFirst(prefix, ""));
            }
          }
        }
      }
    } catch (NamingException exc) {
      // pass
    }
    return ret;
  }

  /**
   * Load known GCP subnets into instance of {@link CidrUtil}
   *
   * <p>This is done via SPF record queries.
   */
  public void loadGcpSubnets() throws IOException {
    int pcnt = 0;
    for (int i = 1; i <= 16; i++) {
      String rdom = String.format("_cloud-netblocks%d.googleusercontent.com", i);
      ArrayList<String> ipents = spfResolver(rdom, "ip4:");
      for (String j : ipents) {
        pcnt++;
        add(j);
      }
      ipents = spfResolver(rdom, "ip6:");
      for (String j : ipents) {
        pcnt++;
        add(j);
      }
    }
    // If we were not able to successfully add any subnet, throw an exception.
    if (pcnt == 0) {
      throw new IOException("unable to process GCP subnet list from SPF records");
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
    subnets.add(new IpAddressMatcher(cidr));
  }

  /** Constructor for {@link CidrUtil}, initialize empty */
  public CidrUtil() {
    subnets = new ArrayList<IpAddressMatcher>();
  }

  /**
   * Constructor for {@link CidrUtil} to load subnet list from resource
   *
   * @param path Resource path or GCS URL to load CIDR subnet list from
   */
  public CidrUtil(String path) throws IOException {
    this();
    ArrayList<String> flist = FileUtil.fileReadLines(path);
    for (String i : flist) {
      add(i);
    }
  }
}
