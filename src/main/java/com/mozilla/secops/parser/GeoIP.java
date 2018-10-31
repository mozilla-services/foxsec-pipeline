package com.mozilla.secops.parser;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;

import java.net.InetAddress;
import java.io.InputStream;
import java.io.IOException;

/**
 * GeoIP resolution
 *
 * <p>Upon initialization, a {@link GeoIP} object will attempt to load database files from specific
 * resource paths in the following order.
 *
 * <p><ul>
 * <li>/GeoLite2-City.mmdb
 * <li>/testdata/GeoIP2-City-Test.mmdb
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
     * Initialize new {@link GeoIP}
     */
    public GeoIP() {
        InputStream in;

        in = GeoIP.class.getResourceAsStream(GEOIP_DBPATH);
        if (in == null) {
            initializingWithTest = true;
            in = GeoIP.class.getResourceAsStream(GEOIP_TESTDBPATH);
            if (in == null) {
                return;
            }
        }

        try {
            geoipDb = new DatabaseReader.Builder(in).build();
            initialized = true;
        } catch (IOException exc) {
            // pass
        }
    }
}
