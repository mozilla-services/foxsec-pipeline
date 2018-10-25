package com.mozilla.secops.alert;

import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.HttpResponse;
import org.apache.http.entity.StringEntity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mozilla.secops.httprequest.Result;
import com.mozilla.secops.crypto.RuntimeSecrets;

import java.util.StringJoiner;
import java.io.IOException;

/**
 * {@link AlertIO} provides an IO transform handling {@link Alert} output
 */
public class AlertIO {
    /**
     * Return {@link PTransform} to handle alerting output
     *
     * @return IO transform
     */
    public static Write write() {
        return new Write();
    }

    /**
     * Handle alerting output based on the contents of the alerting messages such
     * as included metadata and severity.
     */
    public static class Write extends PTransform<PCollection<String>, PDone> {
        private static final long serialVersionUID = 1L;

        /**
         * Create new alert handler transform
         */
        public Write() {
        }

        @Override
        public PDone expand(PCollection<String> input) {
            return PDone.in(input.getPipeline());
        }
    }
}
