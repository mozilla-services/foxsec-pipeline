package com.mozilla.secops.httprequest;

import com.mozilla.secops.input.Input;
import com.mozilla.secops.input.InputElement;
import com.mozilla.secops.parser.ParserCfg;
import org.apache.beam.sdk.testing.TestStream;

/** Various test utilities for HTTPRequest */
public class HTTPRequestUtil {
  /**
   * Return an input stream wired with {@link TestStream}
   *
   * <p>This function currently makes an assumption reads will only be from a single TestStream
   * element, and that all configuration is done via pipeline options. It is essentially a version
   * of HTTPRequest.getInput and can be used with TestStream.
   *
   * @param options Pipeline options
   * @param testStream TestStream
   * @return Input
   */
  public static Input wiredInputStream(
      HTTPRequest.HTTPRequestOptions options, TestStream<String> testStream) throws Exception {
    Input input = new Input().multiplex();
    InputElement e =
        new InputElement(options.getMonitoredResourceIndicator()).addWiredStream(testStream);
    e.setParserConfiguration(ParserCfg.fromInputOptions(options))
        .setEventFilter(HTTPRequestToggles.fromPipelineOptions(options).toStandardFilter());
    input.withInputElement(e);

    // If we are using this we will not be calling getInput in HTTPRequest. Therefore push
    // configuration data into the toggle cache externally, since we will need it later.
    HTTPRequest.addToggleCacheEntry(
        options.getMonitoredResourceIndicator(), HTTPRequestToggles.fromPipelineOptions(options));

    return input;
  }
}
