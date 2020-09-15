package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;

public class FxaContent extends SourcePayloadBase {
  private static final long serialVersionUID = 1L;

  private com.mozilla.secops.parser.models.fxacontent.FxaContent fxaContentData;
  private RequestType requestType;

  public enum RequestType {
    METRICS,
    METRICS_FLOW,
    AUTHORIZATION,
    SIGNIN,
    SIGNUP,
    VALIDATE_EMAIL_DOMAIN,
    OTHER
  }

  private void discernRequestType() {
    String path = fxaContentData.getPath();

    if (path != null) {
      if (path.startsWith("/metrics-flow?")) {
        requestType = RequestType.METRICS_FLOW;
      } else if (path.startsWith("/metrics")) {
        requestType = RequestType.METRICS;
      } else if (path.startsWith("/authorization?")) {
        requestType = RequestType.AUTHORIZATION;
      } else if (path.startsWith("/signin")) {
        requestType = RequestType.SIGNIN;
      } else if (path.startsWith("/signup")) {
        requestType = RequestType.SIGNUP;
      } else if (path.startsWith("/validate-email-domain")) {
        requestType = RequestType.VALIDATE_EMAIL_DOMAIN;
      } else {
        requestType = RequestType.OTHER;
      }
    }
  }

  @Override
  public Boolean matcher(String input, ParserState state) {
    // There should always have an associated Mozlog hint
    Mozlog hint = state.getMozlogHint();
    if (hint == null) {
      return false;
    }
    String logger = hint.getLogger();
    if (logger == null) {
      return false;
    }
    if (logger.equals("fxa-content-server")) {
      return true;
    }
    return false;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.FXACONTENT;
  }

  /**
   * Fetch parsed FxA content data
   *
   * @return FxA content data
   */
  @JsonProperty("fxacontent_data")
  public com.mozilla.secops.parser.models.fxacontent.FxaContent getFxaContentData() {
    return fxaContentData;
  }

  public RequestType getRequestType() {
    return requestType;
  }

  /** Construct matcher object. */
  public FxaContent() {}

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public FxaContent(String input, Event e, ParserState state) {
    ObjectMapper mapper = state.getObjectMapper();
    try {
      fxaContentData =
          state
              .getObjectMapper()
              .readValue(input, com.mozilla.secops.parser.models.fxacontent.FxaContent.class);
      if (fxaContentData == null) {
        return;
      }
    } catch (IOException exc) {
      return;
    }

    // Content server contains both the client address as well as the full address chain
    // It should be fine to use the client address, but if its not available, try to
    // extract it from the chain
    String sa = fxaContentData.getClientAddress();
    if (sa != null) {
      setSourceAddress(sa, state, null);
    } else {
      String rac = fxaContentData.getRemoteAddressChain();
      if (rac != null) {
        ArrayList<String> raca = new ArrayList<>();
        try {
          raca =
              mapper.readValue(
                  rac,
                  mapper.getTypeFactory().constructCollectionType(ArrayList.class, String.class));
          if (raca != null) {
            sa = state.getParser().applyXffAddressSelector(String.join(",", raca));
            if (sa != null) {
              setSourceAddress(sa, state, null);
            }
          }
        } catch (IOException exc) {
          // pass
        }
      }
    }
    discernRequestType();
  }
}
