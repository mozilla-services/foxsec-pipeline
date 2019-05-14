package com.mozilla.secops.parser;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.mozilla.secops.GcsUtil;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicBoolean;

/** GeoIP resolution */
public class GeoIP {
  private static DatabaseReader geoipCityDb = null;
  private static DatabaseReader geoipIspDb = null;
  private static AtomicBoolean cityInitialized = new AtomicBoolean(false);
  private static AtomicBoolean ispInitialized = new AtomicBoolean(false);

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
      return geoipCityDb.city(ia);
    } catch (IOException exc) {
      return null;
    } catch (GeoIp2Exception exc) {
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
      return geoipIspDb.isp(ia);
    } catch (IOException exc) {
      return null;
    } catch (GeoIp2Exception exc) {
      return null;
    }
  }

  private static DatabaseReader getDatabaseFromPath(String path) throws IOException {
    if (path == null) {
      return null;
    }

    InputStream in;
    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = GeoIP.class.getResourceAsStream(path);
    }
    if (in == null) {
      return null;
    }

    return new DatabaseReader.Builder(in).build();
  }

  private static synchronized void initialize(String cityPath, String ispPath) throws IOException {
    if (cityInitialized.get() || ispInitialized.get()) {
      return;
    }

    geoipCityDb = getDatabaseFromPath(cityPath);
    if (geoipCityDb != null) {
      cityInitialized.set(true);
    }
    geoipIspDb = getDatabaseFromPath(ispPath);
    if (geoipIspDb != null) {
      ispInitialized.set(true);
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
