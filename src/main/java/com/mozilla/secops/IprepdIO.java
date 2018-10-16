package com.mozilla.secops;

import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.HttpClient;

public class IprepdIO {
    public static Write write() {
        return new Write();
    }

    public static class Write extends PTransform<PCollection<String>, PDone> {
        private static final long serialVersionUID = 1L;

        @Override
        public PDone expand(PCollection<String> input) {
            input.apply(ParDo.of(new WriteFn(this)));
            return PDone.in(input.getPipeline());
        }
    }

    private static class WriteFn extends DoFn<String, Void> {
        private static final long serialVersionUID = 1L;

        private final Write wTransform;
        private HttpClient httpClient;

        public WriteFn(Write wTransform) {
            this.wTransform = wTransform;
        }

        @Setup
        public void setup() {
            httpClient = HttpClientBuilder.create().build();
        }

        @ProcessElement
        public void processElement(ProcessContext processContext) throws Exception {
        }
    }
}
