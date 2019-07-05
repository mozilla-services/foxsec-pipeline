package com.mozilla.secops.parser;

import com.maxmind.geoip2.model.CityResponse;

/**
 * Extension of {@link PayloadBase} that unifies source address field handling
 *
 * <p>Payload types that manipulate some indication of a source address field should likely inherit
 * from this class.
 */
public abstract class SourcePayloadBase extends PayloadBase {
  private String sourceAddress;
  private String sourceAddressCity;
  private String sourceAddressCountry;
  private Double sourceAddressLatitude;
  private Double sourceAddressLongitude;

  /**
   * Set source address field
   *
   * <p>If the state value is non-null, this function will also attempt to utilize the parser GeoIP
   * instance to set the city and country fields.
   *
   * <p>If n is non-null, the values will also be mirrored into the normalized event fields.*
   *
   * @param sourceAddress Source address
   * @param state Parser state
   * @param n Normalized field from base event
   */
  public void setSourceAddress(String sourceAddress, ParserState state, Normalized n) {
    if (sourceAddress == null) {
      return;
    }
    this.sourceAddress = sourceAddress;

    if (state != null) {
      // If we have parser state attempt to resolve GeoIP information
      CityResponse cr = state.getParser().geoIp(sourceAddress);
      if (cr != null) {
        sourceAddressCity = cr.getCity().getName();
        sourceAddressCountry = cr.getCountry().getIsoCode();

        if ((cr.getLocation() != null)
            && (cr.getLocation().getLatitude() != null)
            && (cr.getLocation().getLongitude() != null)) {
          sourceAddressLatitude = cr.getLocation().getLatitude();
          sourceAddressLongitude = cr.getLocation().getLongitude();
        }
      }
    }

    // If our normalized event is non-null, also set information there
    if (n != null) {
      n.setSourceAddress(sourceAddress);
      n.setSourceAddressCity(sourceAddressCity);
      n.setSourceAddressCountry(sourceAddressCountry);
      n.setSourceAddressLatitude(sourceAddressLatitude);
      n.setSourceAddressLongitude(sourceAddressLongitude);
    }
  }

  /**
   * Set source address field
   *
   * @param sourceAddress Source address
   */
  public void setSourceAddress(String sourceAddress) {
    setSourceAddress(sourceAddress, null, null);
  }

  /**
   * Get source address
   *
   * @return Source address string or null if unset
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
    return sourceAddressCity;
  }

  /**
   * Get source address country
   *
   * @return Source address country field or null if unset
   */
  public String getSourceAddressCountry() {
    return sourceAddressCountry;
  }

  /**
   * Get source address latitude
   *
   * @return Latitude or null if unset
   */
  public Double getSourceAddressLatitude() {
    return sourceAddressLatitude;
  }

  /**
   * Get source address longitude
   *
   * @return Longitude or null if unset
   */
  public Double getSourceAddressLongitude() {
    return sourceAddressLongitude;
  }
}
