package com.mozilla.secops.parser;

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

  private EnumSet<Type> types;

  private String subjectUser;
  private String sourceAddress;
  private String sourceAddressCity;
  private String sourceAddressCountry;
  private String object;
  private String requestMethod;
  private String requestUrl;
  private String urlRequestPath; // Extracted request path component
  private Integer requestStatus;
  private String userAgent;

  /* Following can typically only be set if the parser has been configured
   * to use an identity manager for lookups */
  private String subjectUserIdentity;

  Normalized() {
    types = EnumSet.noneOf(Type.class);
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
   */
  public void setSourceAddress(String addr) {
    sourceAddress = addr;
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
   * Set source address city field
   *
   * @param sourceAddressCity City string value
   */
  public void setSourceAddressCity(String sourceAddressCity) {
    this.sourceAddressCity = sourceAddressCity;
  }

  /**
   * Get source address city field
   *
   * @return Source address city string
   */
  public String getSourceAddressCity() {
    return sourceAddressCity;
  }

  /**
   * Get source address country field
   *
   * @return Source address country string
   */
  public String getSourceAddressCountry() {
    return sourceAddressCountry;
  }

  /**
   * Set source address country field
   *
   * @param sourceAddressCountry Country string value
   */
  public void setSourceAddressCountry(String sourceAddressCountry) {
    this.sourceAddressCountry = sourceAddressCountry;
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
}
