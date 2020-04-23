package com.mozilla.secops.alert;

import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.parser.GeoIP;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.SimpleFunction;

/** {@link DoFn} for normalization and supplemental enrichment of {@link Alert} objects */
public class AlertFormatter extends DoFn<Alert, Alert> {
  private static final long serialVersionUID = 1L;

  private String monitoredResourceIndicator;
  private String[] addressFields;
  private String maxmindCityDbPath;
  private String maxmindIspDbPath;
  private GeoIP geoip;

  /**
   * SimpleFunction for conversion of {@link Alert} objects to JSON string
   *
   * <p>Intended for use with MapElements.
   */
  public static class AlertToString extends SimpleFunction<Alert, String> {
    private static final long serialVersionUID = 1L;

    @Override
    public String apply(Alert input) {
      return input.toJSON();
    }
  }

  /**
   * Initialize new AlertFormatter
   *
   * @param options IOOptions
   */
  public AlertFormatter(IOOptions options) {
    monitoredResourceIndicator = options.getMonitoredResourceIndicator();
    maxmindCityDbPath = options.getMaxmindCityDbPath();
    maxmindIspDbPath = options.getMaxmindIspDbPath();
  }

  /**
   * Initialize new AlertFormatter
   *
   * @param monitoredResourceIndicator Monitored resource indicator
   * @param maxmindCityDbPath Path to Maxmind City DB
   * @param maxmindIspDbPath Path to Maxmind ISP DB
   */
  public AlertFormatter(
      String monitoredResourceIndicator, String maxmindCityDbPath, String maxmindIspDbPath) {
    this.monitoredResourceIndicator = monitoredResourceIndicator;
    this.maxmindCityDbPath = maxmindCityDbPath;
    this.maxmindIspDbPath = maxmindIspDbPath;
  }

  /**
   * Process metadata fields and add GeoIP information
   *
   * @param a Alert
   * @param geoip Initialized GeoIP
   */
  public static void addGeoIPData(Alert a, GeoIP geoip) {
    AlertMeta.Key cityKey, countryKey, ispKey, asnKey, asOrgKey;

    if (geoip == null) {
      return;
    }

    for (AlertMeta.Key k : AlertMeta.IPADDRESS_KEYS) {
      String buf = a.getMetadataValue(k);
      if (buf == null) {
        continue;
      }

      cityKey = k.getAssociatedKey(AlertMeta.Key.AssociatedKey.CITY);
      countryKey = k.getAssociatedKey(AlertMeta.Key.AssociatedKey.COUNTRY);

      if (cityKey != null && countryKey != null) {
        CityResponse cr = geoip.lookupCity(buf);
        if (cr != null) {
          if (cr.getCity() != null) {
            // getName() can return an empty string in some cases
            if (cr.getCity().getName() != null && !cr.getCity().getName().isEmpty()) {
              a.addMetadata(cityKey, cr.getCity().getName());
            }
          }
          a.addMetadata(countryKey, cr.getCountry().getIsoCode());
        }
      }

      ispKey = k.getAssociatedKey(AlertMeta.Key.AssociatedKey.ISP);
      asnKey = k.getAssociatedKey(AlertMeta.Key.AssociatedKey.ASN);
      asOrgKey = k.getAssociatedKey(AlertMeta.Key.AssociatedKey.AS_ORG);

      if (ispKey != null && asnKey != null && asOrgKey != null) {
        IspResponse ir = geoip.lookupIsp(buf);
        if (ir != null) {
          if (ir.getIsp() != null) {
            a.addMetadata(ispKey, ir.getIsp());
          }
          if (ir.getAutonomousSystemNumber() != null) {
            a.addMetadata(asnKey, ir.getAutonomousSystemNumber().toString());
          }
          if (ir.getAutonomousSystemOrganization() != null) {
            a.addMetadata(asOrgKey, ir.getAutonomousSystemOrganization());
          }
        }
      }
    }
  }

  @Setup
  public void setup() {
    if (maxmindCityDbPath != null || maxmindIspDbPath != null) {
      geoip = new GeoIP(maxmindCityDbPath, maxmindIspDbPath);
    }
  }

  @ProcessElement
  public void processElement(ProcessContext c) {
    Alert a = c.element();

    // Add the monitored_resource metadata if missing
    if (a.getMetadataValue(AlertMeta.Key.MONITORED_RESOURCE) == null) {
      if (monitoredResourceIndicator == null) {
        throw new RuntimeException("monitored resource indicator was null in AlertFormatter");
      }
      a.addMetadata(AlertMeta.Key.MONITORED_RESOURCE, monitoredResourceIndicator);
    }

    addGeoIPData(a, geoip);
    c.output(a);
  }
}
