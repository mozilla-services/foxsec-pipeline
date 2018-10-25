package com.mozilla.secops;

import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.transforms.Flatten;

/**
 * Enumeration of input transforms that can be used for initial ingestion in a pipeline.
 */
public enum InputType {
    /** File based input transform based on TextIO */
    file {
        public PTransform<PBegin, PCollection<String>> read(Pipeline p, InputOptions options) {
            String[] inputs = options.getInput();

            return new PTransform<PBegin, PCollection<String>>() {
                private static final long serialVersionUID = 1L;

                @Override
                public PCollection<String> expand(PBegin b) {
                    PCollectionList<String> inputList = PCollectionList.<String>empty(p);
                    for (String s : inputs) {
                        inputList = inputList.and(b.apply(TextIO.read().from(s)));
                    }
                    return inputList.apply(Flatten.<String>pCollections());
                }
            };
        }
    },

    /** Pubsub based input transform based on PubsubIO */
    pubsub {
        public PTransform<PBegin, PCollection<String>> read(Pipeline p, InputOptions options) {
            String[] inputs = options.getInput();

            return new PTransform<PBegin, PCollection<String>>() {
                private static final long serialVersionUID = 1L;

                @Override
                public PCollection<String> expand(PBegin b) {
                    PCollectionList<String> inputList = PCollectionList.<String>empty(p);
                    for (String s : inputs) {
                        inputList = inputList.and(b.apply(PubsubIO.readStrings()
                            .fromTopic(s)));
                    }
                    return inputList.apply(Flatten.<String>pCollections());
                }
            };
        }
    };

    /**
     * The read method can be called on the returned value to obtain a respective
     * {@link PTransform} based on the supplied {@link InputOptions}.
     *
     * @param options {@link InputOptions}
     * @return Configured {@link PTransform}
     */
    public abstract PTransform<PBegin, PCollection<String>> read(Pipeline p, InputOptions options);
}
