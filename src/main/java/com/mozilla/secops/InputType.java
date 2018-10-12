package com.mozilla.secops;

import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;

public enum InputType {
    file {
        public PTransform<PBegin, PCollection<String>> read(InputOptions options) {
            return TextIO.read().from(options.getInput());
        }
    },

    pubsub {
        public PTransform<PBegin, PCollection<String>> read(InputOptions options) {
            return PubsubIO.readStrings().fromTopic(options.getInput());
        }
    };

    public abstract PTransform<PBegin, PCollection<String>> read(InputOptions options);
}
