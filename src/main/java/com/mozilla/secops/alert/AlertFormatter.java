package com.mozilla.secops.alert;

import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.IspResponse;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.parser.GeoIP;
import org.apache.beam.sdk.transforms.DoFn;

/**
 * {@link DoFn} for conversion of {@link Alert} objects into JSON strings
 *
 * <p>This DoFn also supplements the alert with a metadata entry with the monitored resource
 * indicator value, which is a required value in {@link com.mozilla.secops.OutputOptions}.
 */
public class AlertFormatter extends DoFn<Alert, String> {
  private static final long serialVersionUID = 1L;

  private String monitoredResourceIndicator;
  private String[] addressFields;
  private String maxmindCityDbPath;
  private String maxmindIspDbPath;
  private GeoIP geoip;

  public AlertFormatter(IOOptions options) {
    monitoredResourceIndicator = options.getMonitoredResourceIndicator();
    addressFields = options.getAlertAddressFields();
    maxmindCityDbPath = options.getMaxmindCityDbPath();
    maxmindIspDbPath = options.getMaxmindIspDbPath();
  }

  // Add additional GeoIP data if not already present
  private void addGeoIPData(Alert a) {
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
    a.addMetadata("monitored_resource", monitoredResourceIndicator);
    addGeoIPData(a);
    c.output(a.toJSON());
  }
}
