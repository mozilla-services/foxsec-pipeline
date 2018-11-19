package com.mozilla.secops.parser;

import com.maxmind.geoip2.model.CityResponse;

import com.mozilla.secops.identity.IdentityManager;

import java.io.Serializable;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Payload parser for OpenSSH log data
 */
public class OpenSSH extends PayloadBase implements Serializable {
    private final static long serialVersionUID = 1L;

    private final String matchRe = "^\\S{3} \\d{2} [\\d:]+ \\S+ \\S*sshd\\[\\d+\\]: .+";
    private Pattern pattRe;

    private final String authAcceptedRe = "^.* (\\S+) sshd\\[\\d+\\]: Accepted (\\S+) for (\\S+) from (\\S+) " +
        "port (\\d+).*";
    private Pattern pattAuthAcceptedRe;

    private String user;
    private String authMethod;
    private String sourceAddress;
    private String sourceAddressCity;
    private String sourceAddressCountry;
    private String hostname;

    @Override
    public Boolean matcher(String input) {
        Matcher mat = pattRe.matcher(input);
        if (mat.matches()) {
            return true;
        }
        return false;
    }

    @Override
    public Payload.PayloadType getType() {
        return Payload.PayloadType.OPENSSH;
    }

    /**
     * Construct matcher object.
     */
    public OpenSSH() {
        pattRe = Pattern.compile(matchRe);
    }

    /**
     * Construct parser object.
     *
     * @param input Input string.
     * @param e Parent {@link Event}.
     * @param p Parser instance
     */
    public OpenSSH(String input, Event e, Parser p) {
        pattAuthAcceptedRe = Pattern.compile(authAcceptedRe);
        Matcher mat = pattAuthAcceptedRe.matcher(input);
        if (mat.matches()) {
            hostname = mat.group(1);
            authMethod = mat.group(2);
            user = mat.group(3);
            sourceAddress = mat.group(4);
            Normalized n = e.getNormalized();
            n.addType(Normalized.Type.AUTH);
            n.setSubjectUser(user);
            n.setSourceAddress(sourceAddress);
            n.setObject(hostname);

            // If we have an instance of IdentityManager in the parser, see if we can
            // also set the resolved subject identity
            IdentityManager mgr = p.getIdentityManager();
            if (mgr != null) {
                String resId = mgr.lookupAlias(user);
                if (resId != null) {
                    n.setSubjectUserIdentity(resId);
                }
            }

            if (sourceAddress != null) {
                CityResponse cr = p.geoIp(sourceAddress);
                if (cr != null) {
                    sourceAddressCity = cr.getCity().getName();
                    sourceAddressCountry = cr.getCountry().getIsoCode();
                    n.setSourceAddressCity(sourceAddressCity);
                    n.setSourceAddressCountry(sourceAddressCountry);
                }
            }
        }
    }

    /**
     * Get username
     *
     * @return Username
     */
    public String getUser() {
        return user;
    }

    /**
     * Get authentication method
     *
     * @return Authentication method
     */
    public String getAuthMethod() {
        return authMethod;
    }

    /**
     * Get source address
     *
     * @return Source address
     */
    public String getSourceAddress() {
        return sourceAddress;
    }

    /**
     * Get source address city
     *
     * @return Source address city
     */
    public String getSourceAddressCity() {
        return sourceAddressCity;
    }

    /**
     * Get source address country
     *
     * @return Source address country
     */
    public String getSourceAddressCountry() {
        return sourceAddressCountry;
    }

    @Override
    public String eventStringValue(EventFilterPayload.StringProperty property) {
        switch (property) {
            case OPENSSH_AUTHMETHOD:
                return getAuthMethod();
        }
        return null;
    }
}
