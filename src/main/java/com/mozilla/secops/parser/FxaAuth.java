package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import java.io.IOException;
import java.io.Serializable;

/** Payload parser for FxA authentication server log data */
public class FxaAuth extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.fxaauth.FxaAuth fxaAuthData;

  private ObjectMapper getObjectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModule(new JodaModule());
    mapper.configure(
        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
    return mapper;
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    ObjectMapper mapper = getObjectMapper();
    com.mozilla.secops.parser.models.fxaauth.FxaAuth d;
    try {
      d = mapper.readValue(input, com.mozilla.secops.parser.models.fxaauth.FxaAuth.class);
    } catch (IOException exc) {
      return false;
    }
    Mozlog m = state.getMozlogHint();
    if (m == null) {
      return false;
    }
    String logger = m.getLogger();
    if (logger == null) {
      return false;
    }
    if (logger.equals("fxa-auth-server")) {
      return true;
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.FXAAUTH;
  }

  /**
   * Fetch parsed FxA auth data
   *
   * @return FxA auth data
   */
  @JsonProperty("fxaauth_data")
  public com.mozilla.secops.parser.models.fxaauth.FxaAuth getFxaAuthData() {
    return fxaAuthData;
  }

  /** Construct matcher object. */
  public FxaAuth() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public FxaAuth(String input, Event e, ParserState state) {
    ObjectMapper mapper = getObjectMapper();
    try {
      fxaAuthData = mapper.readValue(input, com.mozilla.secops.parser.models.fxaauth.FxaAuth.class);
      if (fxaAuthData == null) {
        return;
      }
    } catch (IOException exc) {
      return;
    }
  }
}
