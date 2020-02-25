package com.mozilla.secops.authprofile;

import com.mozilla.secops.input.Input;
import com.mozilla.secops.input.InputElement;
import com.mozilla.secops.parser.ParserCfg;
import org.apache.beam.sdk.testing.TestStream;

/** Various test utilities for AuthProfile */
public class TestAuthProfileUtil {
  /**
   * Return an input stream wired with {@link TestStream}
   *
   * <p>This function currently makes an assumption reads will only be from a single TestStream
   * element, and that all configuration is done via pipeline options.
   *
   * @param options Pipeline options
   * @param testStream TestStream
   * @return Input
   */
  public static Input wiredInputStream(
      AuthProfile.AuthProfileOptions options, TestStream<String> testStream) throws Exception {
    Input input = new Input().simplex();
    InputElement e =
        new InputElement(options.getMonitoredResourceIndicator()).addWiredStream(testStream);
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      e.setConfigurationTicks(
          AuthProfile.buildConfigurationTick(options),
          options.getGenerateConfigurationTicksInterval(),
          options.getGenerateConfigurationTicksMaximum());
    }
    e.setParserConfiguration(ParserCfg.fromInputOptions(options));
    input.withInputElement(e);

    return input;
  }
}
