package com.mozilla.secops.parser;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.mozilla.secops.FileUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** GeoIP resolution */
public class GeoIP {
  private static DatabaseReader geoipCityDb = null;
  private static DatabaseReader geoipIspDb = null;
  private static Cache<InetAddress, CityResponse> cityCache = null;
  private static Cache<InetAddress, IspResponse> ispCache = null;
  private static AtomicBoolean cityInitialized = new AtomicBoolean(false);
  private static AtomicBoolean ispInitialized = new AtomicBoolean(false);

  private static final int CACHE_MAX_SIZE = 16384;
  private static final int EXPIRY_MINUTES = 15;

  /**
   * Helper class for storing GeoIP related attributes, and for resolving the attributes according
   * to the resolution mode.
   *
   * <p>Objects of this type can integrate heavily with the parser and parser state in order to make
   * use of previously initialized GeoIP classes. In cases where deferred lookups are being used,
   * this class will initialize a new GeoIP object using the configuration parameters stored in the
   * parser configuration for the lookup operation. Because most members of the GeoIP are static and
   * synchronized, the performance impact associated with this should be minimal.
   */
  public static class GeoIPData implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The resolution mode for GeoIP attributes.
     *
     * <p>If set to ON_CREATION, geo-location for IP address values will be performed when the
     * source address field is set in this object.
     *
     * <p>If set to DEFERRED, the resolution will not actually occur until a geo-IP related value is
     * read for the first time. DEFERRED mode can be useful if the geo-IP data is not actually
     * required to be created at the onset of event creation.
     */
    public enum GeoResolutionMode {
      /** Attempt geo-IP resolution on source address set */
      ON_CREATION,
      /** Attempt geo-IP resolution only when a geo-IP related field is read for the first time. */
      DEFERRED
    }

    private GeoResolutionMode resolutionMode;
    private boolean resolutionGeoSet = false;

    private String sourceAddress;
    private String sourceAddressCity;
    private String sourceAddressCountry;
    private Double sourceAddressLatitude;
    private Double sourceAddressLongitude;
    private String sourceTimeZone;
    private String sourceAddressIsp;
    private Integer sourceAddressAsn;
    private String sourceAddressAsOrg;

    private String maxmindCityDbPath;
    private String maxmindIspDbPath;

    private void resolve(GeoIP geoIp) {
      if (resolutionGeoSet) {
        // If we have already resolved the data, just return.
        return;
      }

      if (geoIp == null) {
        // If no GeoIP object was provided, initialize a new one using the previously
        // cached configuration values.
        geoIp = new GeoIP(maxmindCityDbPath, maxmindIspDbPath);
      }

      CityResponse cr = geoIp.lookupCity(sourceAddress);
      if (cr != null) {
        // Note that even with a valid response, sometimes the city and country fields we want can
        // be returned as empty strings. If we see empty strings here treat them the same as if
        // they
        // were null. Also do the same for the ISP related lookups.
        if (cr.getCity() != null) {
          if (cr.getCity().getName() != null && !cr.getCity().getName().isEmpty()) {
            sourceAddressCity = cr.getCity().getName();
          }
        }
        if (cr.getCountry() != null) {
          if (cr.getCountry().getIsoCode() != null && !cr.getCountry().getIsoCode().isEmpty()) {
            sourceAddressCountry = cr.getCountry().getIsoCode();
          }
        }

        if ((cr.getLocation() != null)
            && (cr.getLocation().getLatitude() != null)
            && (cr.getLocation().getLongitude() != null)) {
          sourceAddressLatitude = cr.getLocation().getLatitude();
          sourceAddressLongitude = cr.getLocation().getLongitude();

          if (cr.getLocation().getTimeZone() != null && !cr.getLocation().getTimeZone().isEmpty()) {
            sourceTimeZone = cr.getLocation().getTimeZone();
          }
        }
      }

      IspResponse ir = geoIp.lookupIsp(sourceAddress);
      if (ir != null) {
        if (ir.getIsp() != null && !ir.getIsp().isEmpty()) {
          sourceAddressIsp = ir.getIsp();
        }
        sourceAddressAsn = ir.getAutonomousSystemNumber();
        if (ir.getAutonomousSystemOrganization() != null
            && !ir.getAutonomousSystemOrganization().isEmpty()) {
          sourceAddressAsOrg = ir.getAutonomousSystemOrganization();
        }
      }

      resolutionGeoSet = true;
    }

    /**
     * Set source address field
     *
     * @param sourceAddress Source address
     * @param resolutionMode The GeoIP resolution mode to use
     * @param state Parser state
     */
    public void setSourceAddress(
        String sourceAddress, GeoResolutionMode resolutionMode, ParserState state) {
      this.sourceAddress = sourceAddress;
      this.resolutionMode = resolutionMode;
      if (resolutionMode.equals(GeoResolutionMode.ON_CREATION)) {
        // If we are set to ON_CREATION, attempt geo-ip resolution immediately using the supplied
        // parser state
        resolve(state.getGeoIp());
      } else {
        // Otherwise, obtain the configuration parameters for Maxmind from the parser state so we
        // can reuse them later. Generally the actually database fetch will not occur as the GeoIP
        // object members usually would have already initialized, since it's shared amongst
        // threads.
        maxmindCityDbPath = state.getMaxmindCityDbPath();
        maxmindIspDbPath = state.getMaxmindIspDbPath();
      }
    }

    /**
     * Get source address set in this GeoIPData object
     *
     * @return String
     */
    public String getSourceAddress() {
      return sourceAddress;
    }

    /**
     * Get source address city
     *
     * @return Source address city field or null if unset
     */
    public String getSourceAddressCity() {
      resolve(null);
      return sourceAddressCity;
    }

    /**
     * Get source address country
     *
     * @return Source address country field or null if unset
     */
    public String getSourceAddressCountry() {
      resolve(null);
      return sourceAddressCountry;
    }

    /**
     * Get source address latitude
     *
     * @return Latitude or null if unset
     */
    public Double getSourceAddressLatitude() {
      resolve(null);
      return sourceAddressLatitude;
    }

    /**
     * Get source address longitude
     *
     * @return Longitude or null if unset
     */
    public Double getSourceAddressLongitude() {
      resolve(null);
      return sourceAddressLongitude;
    }

    /**
     * Get source address time zone
     *
     * @return Time zone or null if unset
     */
    public String getSourceAddressTimeZone() {
      resolve(null);
      return sourceTimeZone;
    }

    /**
     * Get source address ISP
     *
     * @return ISP or null if unset
     */
    public String getSourceAddressIsp() {
      resolve(null);
      return sourceAddressIsp;
    }

    /**
     * Get source address ASN
     *
     * @return ASN or null if unset
     */
    public Integer getSourceAddressAsn() {
      resolve(null);
      return sourceAddressAsn;
    }

    /**
     * Get source address AS organization
     *
     * @return AS organization or null if unset
     */
    public String getSourceAddressAsOrg() {
      resolve(null);
      return sourceAddressAsOrg;
    }
  }

  /**
   * Lookup city/country from IP address string
   *
   * @param ip IP address string
   * @return MaxmindDB {@link CityResponse}, or null on failure
   */
  public CityResponse lookupCity(String ip) {
    if (!cityInitialized.get()) {
      return null;
    }

    try {
      InetAddress ia = InetAddress.getByName(ip);
      return cityCache.get(
          ia,
          x -> {
            try {
              return geoipCityDb.city(ia);
            } catch (IOException exc) {
              return null;
            } catch (GeoIp2Exception exc) {
              return null;
            }
          });
    } catch (IOException exc) {
      return null;
    }
  }

  /**
   * Lookup ISP from IP address string
   *
   * @param ip IP address string
   * @return MaxmindDB {@link IspResponse}, or null on failure
   */
  public IspResponse lookupIsp(String ip) {
    if (!ispInitialized.get()) {
      return null;
    }

    try {
      InetAddress ia = InetAddress.getByName(ip);
      return ispCache.get(
          ia,
          x -> {
            try {
              return geoipIspDb.isp(ia);
            } catch (IOException exc) {
              return null;
            } catch (GeoIp2Exception exc) {
              return null;
            }
          });
    } catch (IOException exc) {
      return null;
    }
  }

  private static DatabaseReader getDatabaseFromPath(String path) throws IOException {
    if (path == null) {
      return null;
    }
    InputStream in = FileUtil.getStreamFromPath(path);
    return new DatabaseReader.Builder(in).build();
  }

  private static synchronized void initialize(String cityPath, String ispPath) throws IOException {
    if (cityPath != null && !cityInitialized.get()) {
      if (!cityInitialized.get()) {
        geoipCityDb = getDatabaseFromPath(cityPath);
        cityCache =
            Caffeine.newBuilder()
                .maximumSize(CACHE_MAX_SIZE)
                .expireAfterWrite(EXPIRY_MINUTES, TimeUnit.MINUTES)
                .build();
        if (geoipCityDb != null) {
          cityInitialized.set(true);
        }
      }
    }
    if (ispPath != null && !ispInitialized.get()) {
      geoipIspDb = getDatabaseFromPath(ispPath);
      ispCache =
          Caffeine.newBuilder()
              .maximumSize(CACHE_MAX_SIZE)
              .expireAfterWrite(EXPIRY_MINUTES, TimeUnit.MINUTES)
              .build();
      if (geoipIspDb != null) {
        ispInitialized.set(true);
      }
    }
  }

  /**
   * Initialize new {@link GeoIP}, load databases from specified paths
   *
   * <p>If you don't want to initialize one of the DB's (City or ISP), pass in `null` as the path.
   *
   * @param cityPath Resource or GCS path to load City database from
   * @param ispPath Resource or GCS path to load ISP database from
   */
  public GeoIP(String cityPath, String ispPath) {
    try {
      initialize(cityPath, ispPath);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }
  }
}
