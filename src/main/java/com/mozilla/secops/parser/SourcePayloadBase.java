package com.mozilla.secops.parser;

import java.io.Serializable;

/**
 * Extension of {@link PayloadBase} that unifies source address field handling
 *
 * <p>Payload types that manipulate some indication of a source address field should likely inherit
 * from this class.
 */
public abstract class SourcePayloadBase extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private String sourceAddress;
  private GeoIP.GeoIPData geoIpData;

  /** Initialize SourcePayloadBase */
  public SourcePayloadBase() {
    geoIpData = new GeoIP.GeoIPData();
  }

  /**
   * Set source address field
   *
   * <p>If the state value is non-null, elements within the parser state such as an initialized
   * GeoIP object will be used as part of geo-ip resolution.
   *
   * <p>If n is non-null, the source address value will also be mirrored into the normalized event
   * field.
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

    GeoIP.GeoIPData.GeoResolutionMode mode = GeoIP.GeoIPData.GeoResolutionMode.ON_CREATION;
    if (state != null && state.getDeferGeoIpResolution()) {
      mode = GeoIP.GeoIPData.GeoResolutionMode.DEFERRED;
    }
    geoIpData.setSourceAddress(sourceAddress, mode, state);

    // If we also have a normalized event object here, also set the source address field
    // for that object.
    if (n != null) {
      n.setSourceAddress(sourceAddress, state);
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
    return geoIpData.getSourceAddressCity();
  }

  /**
   * Get source address country
   *
   * @return Source address country field or null if unset
   */
  public String getSourceAddressCountry() {
    return geoIpData.getSourceAddressCountry();
  }

  /**
   * Get source address latitude
   *
   * @return Latitude or null if unset
   */
  public Double getSourceAddressLatitude() {
    return geoIpData.getSourceAddressLatitude();
  }

  /**
   * Get source address longitude
   *
   * @return Longitude or null if unset
   */
  public Double getSourceAddressLongitude() {
    return geoIpData.getSourceAddressLongitude();
  }

  /**
   * Get source address time zone
   *
   * @return Time zone or null if unset
   */
  public String getSourceAddressTimeZone() {
    return geoIpData.getSourceAddressTimeZone();
  }

  /**
   * Get source address ISP
   *
   * @return ISP or null if unset
   */
  public String getSourceAddressIsp() {
    return geoIpData.getSourceAddressIsp();
  }

  /**
   * Get source address ASN
   *
   * @return ASN or null if unset
   */
  public Integer getSourceAddressAsn() {
    return geoIpData.getSourceAddressAsn();
  }

  /**
   * Get source address AS organization
   *
   * @return AS organization or null if unset
   */
  public String getSourceAddressAsOrg() {
    return geoIpData.getSourceAddressAsOrg();
  }
}
