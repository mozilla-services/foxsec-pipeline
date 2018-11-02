package com.mozilla.secops.parser;

import java.io.Serializable;
import java.util.EnumSet;

/**
 * Normalized event data
 */
public class Normalized implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * Normalized event types
     */
    public enum Type {
        /** Authentication event */
        AUTH
    }

    private EnumSet<Type> types;

    private String subjectUser;
    private String sourceAddress;
    private String sourceAddressCity;
    private String sourceAddressCountry;
    private String object;

    /* Following can typically only be set if the parser has been configured
     * to use an identity manager for lookups */
    private String subjectUserIdentity;

    Normalized() {
        types = EnumSet.noneOf(Type.class);
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
}
