package com.mozilla.secops.customs;

import com.mozilla.secops.input.Input;
import com.mozilla.secops.input.InputElement;
import com.mozilla.secops.parser.ParserCfg;
import org.apache.beam.sdk.testing.TestStream;

/** Various test utilities for Customs */
public class TestCustomsUtil {
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
      Customs.CustomsOptions options, TestStream<String> testStream) throws Exception {
    Input input = new Input().simplex();
    InputElement e =
        new InputElement(options.getMonitoredResourceIndicator()).addWiredStream(testStream);
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      e.setConfigurationTicks(
          Customs.buildConfigurationTick(options),
          options.getGenerateConfigurationTicksInterval(),
          options.getGenerateConfigurationTicksMaximum());
    }
    e.setParserConfiguration(ParserCfg.fromInputOptions(options));
    input.withInputElement(e);

    return input;
  }
}
