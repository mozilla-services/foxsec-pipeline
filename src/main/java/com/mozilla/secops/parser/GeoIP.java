package com.mozilla.secops.parser;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.GcsUtil;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;

/** GeoIP resolution */
public class GeoIP {
  private DatabaseReader geoipDb;
  private Boolean initialized = false;

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
   * Initialize new {@link GeoIP}, load database from specified path
   *
   * @param path Resource or GCS path to load database from
   */
  public GeoIP(String path) {
    InputStream in;

    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = GeoIP.class.getResourceAsStream(path);
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
}
