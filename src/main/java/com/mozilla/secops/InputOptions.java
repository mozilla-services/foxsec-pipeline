package com.mozilla.secops;

import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.Validation;

public interface InputOptions extends PipelineOptions {
    @Description("Type of --input; must be one of [pubsub, file]")
    @Default.Enum("file")
    InputType getInputType();
    void setInputType(InputType value);

    @Description("Input to read from; file path, Pubsub topic")
    @Validation.Required
    String getInput();
    void setInput(String value);
}
