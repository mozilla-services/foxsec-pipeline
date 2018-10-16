package com.mozilla.secops;

import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PDone;
import org.apache.beam.sdk.values.PCollection;

/**
 * {@link CompositeOutput} provides a standardized composite output transform for use in
 * pipelines.
 */
public abstract class CompositeOutput {
    private CompositeOutput() {}

    /**
     * Return a new composite output transform that can be used as the final stage in a pipeline.
     *
     * <p>{@link OutputOptions} can be used to configure the output phase.
     *
     * @param options {@link OutputOptions} used to configure returned {@link PTransform}.
     * @return Configured {@link PTransform}
     */
    public static PTransform<PCollection<String>, PDone> withOptions(OutputOptions options) {
        return new PTransform<PCollection<String>, PDone>() {
            private static final long serialVersionUID = 1L;

            @Override
            public PDone expand(PCollection<String> input) {
                if (options.getOutputFile() != null) {
                    input.apply(TextIO.write().to(options.getOutputFile()));
                }
                return PDone.in(input.getPipeline());
            }
        };
    }
}
