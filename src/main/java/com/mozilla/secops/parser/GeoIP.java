package com.mozilla.secops.parser;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.GcsUtil;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicBoolean;

/** GeoIP resolution */
public class GeoIP {
  private static DatabaseReader geoipDb = null;
  private static AtomicBoolean initialized = new AtomicBoolean(false);

  /**
   * Lookup city/country from IP address string
   *
   * @param ip IP address string
   * @return MaxmindDB {@link CityResponse}, or null on failure
   */
  public CityResponse lookup(String ip) {
    if (!initialized.get()) {
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

  private static synchronized void initialize(String path) throws IOException {
    InputStream in;

    if (initialized.get()) {
      return;
    }

    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = GeoIP.class.getResourceAsStream(path);
    }
    if (in == null) {
      return;
    }

    geoipDb = new DatabaseReader.Builder(in).build();
    initialized.set(true);
  }

  /**
   * Initialize new {@link GeoIP}, load database from specified path
   *
   * @param path Resource or GCS path to load database from
   */
  public GeoIP(String path) {
    try {
      initialize(path);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }
  }
}
