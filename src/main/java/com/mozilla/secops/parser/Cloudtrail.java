package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;

import com.maxmind.geoip2.model.CityResponse;

import com.mozilla.secops.parser.models.cloudtrail.CloudtrailEvent;
import com.mozilla.secops.identity.IdentityManager;

import java.io.IOException;
import java.io.Serializable;
import java.util.Map;

/**
 * Payload parser for Cloudtrail events
 */
public class Cloudtrail extends PayloadBase implements Serializable {
    private static final long serialVersionUID = 1L;

    private ObjectMapper mapper;

    private CloudtrailEvent event;

    private String sourceAddressCity;
    private String sourceAddressCountry;

    @Override
    public Boolean matcher(String input) {
        try {
            event = mapper.readValue(input, CloudtrailEvent.class);
            if (event.getEventVersion() == null) {
                return false;
            }
            if (Double.parseDouble(event.getEventVersion()) > 1.00) {
                return true;
            }
        } catch (IOException exc) {
            // pass
        }
        return false;
    }

    @Override
    public Payload.PayloadType getType() {
        return Payload.PayloadType.CLOUDTRAIL;
    }

    /**
     * Construct matcher object.
     */
    public Cloudtrail() {
        mapper = getObjectMapper();
    }

    /**
     * Construct parser object.
     *
     * @param input Input string.
     * @param e Parent {@link Event}.
     * @param p Parser instance.
     */
    public Cloudtrail(String input, Event e, Parser p) {
        mapper = getObjectMapper();
        try {
            event = mapper.readValue(input, CloudtrailEvent.class);
            if (isAuthEvent()) {
                Normalized n = e.getNormalized();
                n.setType(Normalized.Type.AUTH);
                n.setSubjectUser(getUser());
                n.setSourceAddress(getSourceAddress());
                n.setObject(event.getRecipientAccountID());

                // TODO: Consider moving identity management into Normalized

                // If we have an instance of IdentityManager in the parser, see if we can
                // also set the resolved subject identity
                IdentityManager mgr = p.getIdentityManager();
                if (mgr != null) {
                    String resId = mgr.lookupAlias(getUser());
                    if (resId != null) {
                        n.setSubjectUserIdentity(resId);
                    }
                    Map<String, String> m = mgr.getAwsAccountMap();
                    String accountName = m.get(event.getRecipientAccountID());
                    if (accountName != null) {
                        n.setObject(accountName);
                    } else {
                        n.setObject(event.getRecipientAccountID());
                    }
                }

                if (getSourceAddress() != null) {
                    CityResponse cr = p.geoIp(getSourceAddress());
                    if (cr != null) {
                        sourceAddressCity = cr.getCity().getName();
                        sourceAddressCountry = cr.getCountry().getIsoCode();
                        n.setSourceAddressCity(sourceAddressCity);
                        n.setSourceAddressCountry(sourceAddressCountry);
                    }
                }
            }
        } catch (IOException exc) {
            return;
        }
    }

    private ObjectMapper getObjectMapper() {
        ObjectMapper _mapper = new ObjectMapper();
        _mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        return _mapper;
    }

    /**
     * Get username
     *
     * @return Username
     */
    public String getUser() {
        return event.getIdentityName();
    }

    /**
     * Get source address
     *
     * @return Source address
     */
    public String getSourceAddress() {
        return event.getSourceIPAddress();
    }


    private Boolean isAuthEvent() {
        if (event.getEventName().equals("ConsoleLogin")) {
            if (event.getEventType().equals("AwsConsoleSignIn") &&
                event.getResponseElementsValue("ConsoleLogin") != null &&
                event.getResponseElementsValue("ConsoleLogin").equals("Success")) {
                return true;
            }
        }
        if (event.getEventName().equals("AssumeRole")) {
            if (event.getUserType().equals("IAMUser") && event.getErrorCode() == null) {
                return true;
            }
        }
        return false;
    }
}
