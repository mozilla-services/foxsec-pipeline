package com.mozilla.secops;

import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;

/**
 * Enumeration of input transforms that can be used for initial ingestion in a pipeline.
 */
public enum InputType {
    /** File based input transform based on TextIO */
    file {
        public PTransform<PBegin, PCollection<String>> read(InputOptions options) {
            return TextIO.read().from(options.getInput());
        }
    },

    /** Pubsub based input transform based on PubsubIO */
    pubsub {
        public PTransform<PBegin, PCollection<String>> read(InputOptions options) {
            return PubsubIO.readStrings().fromTopic(options.getInput());
        }
    };

    /**
     * The read method can be called on the returned value to obtain a respective
     * {@link PTransform} based on the supplied {@link InputOptions}.
     *
     * @param options {@link InputOptions}
     * @return Configured {@link PTransform}
     */
    public abstract PTransform<PBegin, PCollection<String>> read(InputOptions options);
}
