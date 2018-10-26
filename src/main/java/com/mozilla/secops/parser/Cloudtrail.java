package com.mozilla.secops.parser;

import java.io.IOException;
import java.io.Serializable;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;

import com.mozilla.secops.models.CloudtrailEvent;

public class Cloudtrail extends PayloadBase implements Serializable {
    private static final long serialVersionUID = 1L;

    private final ObjectMapper mapper = getObjectMapper();

    private CloudtrailEvent event;

    @Override
    public Boolean matcher(String input) {
        try {
          event = mapper.readValue(input, CloudtrailEvent.class);
          if (Double.parseDouble(event.getEventVersion()) > 1.00) {
            return true;
          }
        } catch (IOException exc) {
          // pass
        } catch (NullPointerException exc) {
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
    public Cloudtrail() {}

    /**
     * Construct parser object.
     *
     * @param input Input string.
     * @param e Parent {@link Event}.
     */
    public Cloudtrail(String input, Event e) {
        try {
            event = mapper.readValue(input, CloudtrailEvent.class);
            if (isAuthEvent()) {
              Normalized n = e.getNormalized();
              n.setType(Normalized.Type.AUTH);
              n.setSubjectUser(getUser());
              n.setSourceAddress(getSourceAddress());
              //TODO
              //n.setObject();
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

    public String getSourceAddress() {
      return event.getSourceIPAddress();
    }

    public String getUser() {
      return event.getIdentityName();
    }

    private Boolean isAuthEvent() {
      if (event.getEventName().equals("ConsoleLogin")) {
        if (event.getEventType().equals("AwsConsoleSignIn") &&
              event.responseElements.get("ConsoleLogin").equals("Success")) {
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
