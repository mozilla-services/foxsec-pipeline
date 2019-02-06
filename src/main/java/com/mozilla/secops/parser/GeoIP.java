package com.mozilla.secops.parser;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.GcsUtil;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;

/**
 * GeoIP resolution
 *
 * <p>Upon initialization, if the constructor is called with no arguments the object will attempt to
 * load database files from specific resource paths in the following order.
 *
 * <p>
 *
 * <ul>
 *   <li>/GeoLite2-City.mmdb
 *   <li>/testdata/GeoIP2-City-Test.mmdb
 * </ul>
 *
 * <p>If the test database is used, the usingTest function will return true.
 */
public class GeoIP {
  private final String GEOIP_TESTDBPATH = "/testdata/GeoIP2-City-Test.mmdb";
  private final String GEOIP_DBPATH = "/GeoLite2-City.mmdb";

  private DatabaseReader geoipDb;
  private Boolean initialized = false;
  private Boolean initializingWithTest = false;

  /**
   * Lookup city/country from IP address string
   *
   * @param ip IP address string
   * @return MaxmindDB {@link CityResponse}, or null on failure
   */
  public CityResponse lookup(String ip) {
    if (!initialized) {
      return null;
    }

    try {
      InetAddress ia = InetAddress.getByName(ip);
      return geoipDb.city(ia);
    } catch (IOException exc) {
      return null;
    } catch (GeoIp2Exception exc) {
      return null;
    }
  }

  /**
   * Indicate if {@link GeoIP} initialized with testing database
   *
   * @return True if testing database is configured
   */
  public Boolean usingTest() {
    return initializingWithTest;
  }

  /**
   * Initialize new {@link GeoIP}, load database from specified path
   *
   * @param path Resource or GCS path to load database from
   */
  public GeoIP(String path) {
    InputStream in;

    // If the specified path was null, try to load the database from the default path locations
    if (path == null) {
      in = GeoIP.class.getResourceAsStream(GEOIP_DBPATH);
      if (in == null) {
        initializingWithTest = true;
        in = GeoIP.class.getResourceAsStream(GEOIP_TESTDBPATH);
      }
    } else {
      if (GcsUtil.isGcsUrl(path)) {
        in = GcsUtil.fetchInputStreamContent(path);
      } else {
        in = GeoIP.class.getResourceAsStream(path);
      }
    }
    if (in == null) {
      return;
    }

    try {
      geoipDb = new DatabaseReader.Builder(in).build();
      initialized = true;
    } catch (IOException exc) {
      // pass
    }
  }

  /** Initialize new {@link GeoIP}, load database from default paths */
  public GeoIP() {
    this(null);
  }
}
