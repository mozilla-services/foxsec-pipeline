package com.mozilla.secops.parser;

import com.maxmind.minfraud.response.InsightsResponse;
import com.mozilla.secops.Minfraud;
import java.io.Serializable;
import java.util.EnumSet;

/** Normalized event data */
public class Normalized implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Normalized event types */
  public enum Type {
    /** Authentication event */
    AUTH,
    /** Indicates an authenticated session, where authentication may have occurred in the past */
    AUTH_SESSION,
    /** Indicates an HTTP request, from something like a web server or a load balancer log */
    HTTP_REQUEST
  }

  /**
   * Status tags is used to track processing state, for example if an event needs additional
   * analysis after the parsing step
   */
  public enum StatusTag {
    /* An event that is missing key information and needs some sort of modification */
    REQUIRES_SUBJECT_USER_FIXUP,
    /* An event that has been fixed up after the parsing step */
    SUBJECT_USER_HAS_BEEN_FIXED
  }

  private EnumSet<Type> types;
  private EnumSet<StatusTag> statusTags;

  private String subjectUser;
  private String sourceAddress;
  private GeoIP.GeoIPData geoIpData;
  private Double sourceAddressRiskScore;
  private Boolean sourceAddressIsAnonymous;
  private Boolean sourceAddressIsAnonymousVpn;
  private Boolean sourceAddressIsHostingProvider;
  private Boolean sourceAddressIsLegitimateProxy;
  private Boolean sourceAddressIsPublicProxy;
  private Boolean sourceAddressIsTorExitNode;
  private String object;
  private String requestMethod;
  private String requestUrl;
  private String urlRequestPath; // Extracted request path component
  private String urlRequestHost; // Extracted request host component
  private Integer requestStatus;
  private String userAgent;

  /* Following can typically only be set if the parser has been configured
   * to use an identity manager for lookups */
  private String subjectUserIdentity;

  Normalized() {
    types = EnumSet.noneOf(Type.class);
    statusTags = EnumSet.noneOf(StatusTag.class);
    geoIpData = new GeoIP.GeoIPData();
  }

  /**
   * Return a given normalized payload field based on the supplied field identifier
   *
   * @param property {@link EventFilterPayload.StringProperty}
   * @return String value or null
   */
  public String eventStringValue(EventFilterPayload.StringProperty property) {
    switch (property) {
      case NORMALIZED_SUBJECTUSER:
        return getSubjectUser();
      case NORMALIZED_REQUESTMETHOD:
        return getRequestMethod();
      case NORMALIZED_REQUESTURL:
        return getRequestUrl();
      case NORMALIZED_URLREQUESTPATH:
        return getUrlRequestPath();
      case NORMALIZED_URLREQUESTHOST:
        return getUrlRequestHost();
      case NORMALIZED_SOURCEADDRESS:
        return getSourceAddress();
    }
    return null;
  }

  /**
   * Return a given normalized payload field based on the supplied field identifier
   *
   * @param property {@link EventFilterPayload.IntegerProperty}
   * @return Integer value or null
   */
  public Integer eventIntegerValue(EventFilterPayload.IntegerProperty property) {
    switch (property) {
      case NORMALIZED_REQUESTSTATUS:
        return requestStatus;
    }
    return null;
  }

  /**
   * Test if normalized event is of a given type
   *
   * @param t {@link Normalized.Type}
   * @return True if type is set in normalized data fields
   */
  public Boolean isOfType(Type t) {
    return types.contains(t);
  }

  /**
   * Add a type flag to normalized type
   *
   * @param t {@link Normalized.Type}
   */
  public void addType(Type t) {
    types.add(t);
  }

  /**
   * Set normalized data type
   *
   * @param t {@link Normalized.Type}
   */
  public void setType(Type t) {
    types = EnumSet.of(t);
  }

  /**
   * Test if normalized event has a given StatusTag
   *
   * @param st {@link Normalized.StatusTag}
   * @return True if tag is set for this event
   */
  public Boolean hasStatusTag(StatusTag st) {
    return statusTags.contains(st);
  }

  /**
   * Add a StatusTag to a normalized event
   *
   * @param st {@link Normalized.StatusTag}
   */
  public void addStatusTag(StatusTag st) {
    statusTags.add(st);
  }

  /**
   * Set normalized status tag
   *
   * @param st {@link Normalized.StatusTag}
   */
  public void setStatusTag(StatusTag st) {
    statusTags = EnumSet.of(st);
  }

  /**
   * Set subject user field
   *
   * @param user Username
   */
  public void setSubjectUser(String user) {
    subjectUser = user;
  }

  /**
   * Set source address field
   *
   * @param addr Source address
   * @param state Parser state
   */
  public void setSourceAddress(String addr, ParserState state) {
    sourceAddress = addr;

    GeoIP.GeoIPData.GeoResolutionMode mode = GeoIP.GeoIPData.GeoResolutionMode.ON_CREATION;
    if (state != null && state.getDeferGeoIpResolution()) {
      mode = GeoIP.GeoIPData.GeoResolutionMode.DEFERRED;
    }
    geoIpData.setSourceAddress(sourceAddress, mode, state);
  }

  /**
   * Set source address field
   *
   * @param addr Source address
   */
  public void setSourceAddress(String addr) {
    setSourceAddress(addr, null);
  }

  /**
   * Set object field
   *
   * @param object Object being authenticated to
   */
  public void setObject(String object) {
    this.object = object;
  }

  /**
   * Get subject user field
   *
   * @return Username
   */
  public String getSubjectUser() {
    return subjectUser;
  }

  /**
   * Get subject user identity field
   *
   * @return Subject user identity
   */
  public String getSubjectUserIdentity() {
    return subjectUserIdentity;
  }

  /**
   * Set subject user identity field
   *
   * @param subjectUserIdentity Resolved identity value
   */
  public void setSubjectUserIdentity(String subjectUserIdentity) {
    this.subjectUserIdentity = subjectUserIdentity;
  }

  /**
   * Get source address field
   *
   * @return Source address
   */
  public String getSourceAddress() {
    return sourceAddress;
  }

  /**
   * Get object field
   *
   * @return Object string
   */
  public String getObject() {
    return object;
  }

  /**
   * Get source address city field
   *
   * @return Source address city string
   */
  public String getSourceAddressCity() {
    return geoIpData.getSourceAddressCity();
  }

  /**
   * Get source address country field
   *
   * @return Source address country string
   */
  public String getSourceAddressCountry() {
    return geoIpData.getSourceAddressCountry();
  }

  /**
   * Get source address time zone field
   *
   * @return Source address time zone, or null if not present
   */
  public String getSourceAddressTimeZone() {
    return geoIpData.getSourceAddressTimeZone();
  }

  /**
   * Get source address latitude
   *
   * @return Source address latitude
   */
  public Double getSourceAddressLatitude() {
    return geoIpData.getSourceAddressLatitude();
  }

  /**
   * Get source address longitude
   *
   * @return Source address longitude
   */
  public Double getSourceAddressLongitude() {
    return geoIpData.getSourceAddressLongitude();
  }

  /**
   * Get source address ISP
   *
   * @return ISP string or null if unset
   */
  public String getSourceAddressIsp() {
    return geoIpData.getSourceAddressIsp();
  }

  /**
   * Get source address ASN
   *
   * @return ASN integer or null if unset
   */
  public Integer getSourceAddressAsn() {
    return geoIpData.getSourceAddressAsn();
  }

  /**
   * Get source address AS organization
   *
   * @return AS organization string or null if unset
   */
  public String getSourceAddressAsOrg() {
    return geoIpData.getSourceAddressAsOrg();
  }

  /**
   * Get source address risks core from minfraud
   *
   * @return Source address risk score
   */
  public Double getSourceAddressRiskScore() {
    return sourceAddressRiskScore;
  }

  /**
   * Set source address risks core from minfraud
   *
   * @param sourceAddressRiskScore riskscore value
   */
  void setSourceAddressRiskScore(Double sourceAddressRiskScore) {
    this.sourceAddressRiskScore = sourceAddressRiskScore;
  }

  /**
   * Get source address isanonymous
   *
   * @return True if source address is apart of an anonmity network
   */
  public Boolean getSourceAddressIsAnonymous() {
    return sourceAddressIsAnonymous;
  }

  /**
   * Set source address isanonymous
   *
   * @param sourceAddressIsAnonymous isanonymous value
   */
  void setSourceAddressIsAnonymous(Boolean sourceAddressIsAnonymous) {
    this.sourceAddressIsAnonymous = sourceAddressIsAnonymous;
  }

  /**
   * Get source address isanonymousvpn
   *
   * @return True if source address is an anonymous vpn
   */
  public Boolean getSourceAddressIsAnonymousVpn() {
    return sourceAddressIsAnonymousVpn;
  }

  /**
   * Set source address isanonymousvpn
   *
   * @param sourceAddressIsAnonymousVpn isanonymous value
   */
  void setSourceAddressIsAnonymousVpn(Boolean sourceAddressIsAnonymous) {
    this.sourceAddressIsAnonymousVpn = sourceAddressIsAnonymous;
  }

  /**
   * Get source address ishostingprovider
   *
   * @return True if source address is from a hosting provider
   */
  public Boolean getSourceAddressIsHostingProvider() {
    return sourceAddressIsHostingProvider;
  }

  /**
   * Set source address ishostingprovider
   *
   * @param sourceAddressIsHostingProvider ishostingprovider value
   */
  void setSourceAddressIsHostingProvider(Boolean sourceAddressIsHostingProvider) {
    this.sourceAddressIsHostingProvider = sourceAddressIsHostingProvider;
  }

  /**
   * Get source address islegitimateproxy
   *
   * @return True if source address is a legitimate proxy
   */
  public Boolean getSourceAddressIsLegitimateProxy() {
    return sourceAddressIsLegitimateProxy;
  }

  /**
   * Set source address islegitimateproxy
   *
   * @param sourceAddressIsLegitimateProxy islegitimateproxy value
   */
  void setSourceAddressIsLegitimateProxy(Boolean sourceAddressIsLegitimateProxy) {
    this.sourceAddressIsLegitimateProxy = sourceAddressIsLegitimateProxy;
  }

  /**
   * Get source address ispublicproxy
   *
   * @return True if source address is a public proxy
   */
  public Boolean getSourceAddressIsPublicProxy() {
    return sourceAddressIsPublicProxy;
  }

  /**
   * Set source address ispublicproxy
   *
   * @param sourceAddressIsPublicProxy ispublicproxy value
   */
  void setSourceAddressIsPublicProxy(Boolean sourceAddressIsPublicProxy) {
    this.sourceAddressIsPublicProxy = sourceAddressIsPublicProxy;
  }

  /**
   * Get source address istorexitnode
   *
   * @return True if source address is a tor exit node
   */
  public Boolean getSourceAddressIsTorExitNode() {
    return sourceAddressIsTorExitNode;
  }

  /**
   * Set source address istorexitnode
   *
   * @param sourceAddressIsTorExitNode istorexitnode value
   */
  void setSourceAddressIsTorExitNode(Boolean sourceAddressIsTorExitNode) {
    this.sourceAddressIsTorExitNode = sourceAddressIsTorExitNode;
  }

  /**
   * Get request method field
   *
   * @return Request method string
   */
  public String getRequestMethod() {
    return requestMethod;
  }

  /**
   * Set request method field
   *
   * @param requestMethod Request method
   */
  public void setRequestMethod(String requestMethod) {
    this.requestMethod = requestMethod;
  }

  /**
   * Get request URL field
   *
   * @return Request URL field
   */
  public String getRequestUrl() {
    return requestUrl;
  }

  /**
   * Set request URL field
   *
   * @param requestUrl Request URL
   */
  public void setRequestUrl(String requestUrl) {
    this.requestUrl = requestUrl;
  }

  /**
   * Get extracted URL request path field
   *
   * @return Request path field
   */
  public String getUrlRequestPath() {
    return urlRequestPath;
  }

  /**
   * Set extracted URL request path field
   *
   * @param urlRequestPath Extracted request path
   */
  public void setUrlRequestPath(String urlRequestPath) {
    this.urlRequestPath = urlRequestPath;
  }

  /**
   * Get extracted URL request host component
   *
   * @return Request host field
   */
  public String getUrlRequestHost() {
    return urlRequestHost;
  }

  /**
   * Set extracted URL request host field
   *
   * @param urlRequestHost Extracted request host
   */
  public void setUrlRequestHost(String urlRequestHost) {
    this.urlRequestHost = urlRequestHost;
  }

  /**
   * Get request status
   *
   * @return Request status field
   */
  public Integer getRequestStatus() {
    return requestStatus;
  }

  /**
   * Set request status
   *
   * @param requestStatus Request status
   */
  public void setRequestStatus(Integer requestStatus) {
    this.requestStatus = requestStatus;
  }

  /**
   * Get user agent
   *
   * @return User agent field
   */
  public String getUserAgent() {
    return userAgent;
  }

  /**
   * Set user agent
   *
   * @param userAgent User agent
   */
  public void setUserAgent(String userAgent) {
    this.userAgent = userAgent;
  }

  /**
   * Include details from Minfraud Insights into Normalized
   *
   * <p>Will do nothing if sourceAddress is null
   *
   * @param mf Minfraud client
   * @return True if enrichment was successful, false otherwise
   */
  public boolean insightsEnrichment(Minfraud mf) {
    if (sourceAddress == null) {
      return false;
    }
    InsightsResponse ir = mf.getInsights(sourceAddress, null);
    if (ir != null) {
      setSourceAddressRiskScore(ir.getIpAddress().getRisk());
      setSourceAddressIsAnonymous(ir.getIpAddress().getTraits().isAnonymous());
      setSourceAddressIsAnonymousVpn(ir.getIpAddress().getTraits().isAnonymousVpn());
      setSourceAddressIsHostingProvider(ir.getIpAddress().getTraits().isHostingProvider());
      setSourceAddressIsLegitimateProxy(ir.getIpAddress().getTraits().isLegitimateProxy());
      setSourceAddressIsPublicProxy(ir.getIpAddress().getTraits().isPublicProxy());
      setSourceAddressIsTorExitNode(ir.getIpAddress().getTraits().isTorExitNode());
      return true;
    }
    return false;
  }
}
