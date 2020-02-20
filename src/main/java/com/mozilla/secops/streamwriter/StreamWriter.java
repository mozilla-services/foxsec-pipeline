package com.mozilla.secops.streamwriter;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.input.Input;
import java.io.IOException;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;

/**
 * Simple IO stream writer
 *
 * <p>Connects composite input with output transforms.
 */
public class StreamWriter implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for {@link StreamWriter} pipeline. */
  public interface StreamWriterOptions extends PipelineOptions, InputOptions, OutputOptions {}

  private static void runStreamWriter(StreamWriterOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    p.apply("input", Input.compositeInputAdapter(options, null))
        .apply(OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   * @throws IOException IOException
   */
  public static void main(String[] args) throws IOException {
    PipelineOptionsFactory.register(StreamWriterOptions.class);
    StreamWriterOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(StreamWriterOptions.class);
    runStreamWriter(options);
  }
}
