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
    addressFields = options.getAlertAddressFields();
    maxmindCityDbPath = options.getMaxmindCityDbPath();
    maxmindIspDbPath = options.getMaxmindIspDbPath();
  }

  /**
   * Initialize new AlertFormatter
   *
   * @param monitoredResourceIndicator Monitored resource indicator
   * @param addressFields Array of address fields
   * @param maxmindCityDbPath Path to Maxmind City DB
   * @param maxmindIspDbPath Path to Maxmind ISP DB
   */
  public AlertFormatter(
      String monitoredResourceIndicator,
      String[] addressFields,
      String maxmindCityDbPath,
      String maxmindIspDbPath) {
    this.monitoredResourceIndicator = monitoredResourceIndicator;
    this.addressFields = addressFields;
    this.maxmindCityDbPath = maxmindCityDbPath;
    this.maxmindIspDbPath = maxmindIspDbPath;
  }

  /**
   * Process metadata fields and add GeoIP information
   *
   * @param a Alert
   * @param addressFields Array of metadata keys to treat as address fields
   * @param geoip Initialized GeoIP
   */
  public static void addGeoIPData(Alert a, String[] addressFields, GeoIP geoip) {
    if (geoip == null || addressFields == null) {
      return;
    }

    for (String addressField : addressFields) {
      String address = a.getMetadataValue(addressField);
      if (address != null) {
        if (a.getMetadataValue(addressField + "_city") == null
            && a.getMetadataValue(addressField + "_country") == null) {
          CityResponse cr = geoip.lookupCity(address);
          if (cr != null) {
            a.addMetadata(addressField + "_city", cr.getCity().getName());
            a.addMetadata(addressField + "_country", cr.getCountry().getIsoCode());
          }
        }
        if (a.getMetadataValue(addressField + "_isp") == null
            && a.getMetadataValue(addressField + "_asn") == null
            && a.getMetadataValue(addressField + "_as_org") == null) {
          IspResponse ir = geoip.lookupIsp(address);
          if (ir != null) {
            if (ir.getIsp() != null) {
              a.addMetadata(addressField + "_isp", ir.getIsp());
            }
            if (ir.getAutonomousSystemNumber() != null) {
              a.addMetadata(addressField + "_asn", ir.getAutonomousSystemNumber().toString());
            }
            if (ir.getAutonomousSystemOrganization() != null) {
              a.addMetadata(addressField + "_as_org", ir.getAutonomousSystemOrganization());
            }
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
    if (a.getMetadataValue("monitored_resource") == null) {
      if (monitoredResourceIndicator == null) {
        throw new RuntimeException("monitored resource indicator was null in AlertFormatter");
      }
      a.addMetadata("monitored_resource", monitoredResourceIndicator);
    }

    addGeoIPData(a, addressFields, geoip);
    c.output(a);
  }
}
