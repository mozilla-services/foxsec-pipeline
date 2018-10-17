package com.mozilla.secops;

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

import java.util.StringJoiner;

/**
 * {@link IprepdIO} provides an IO transform for writing violation messages to iprepd
 */
public class IprepdIO {
    /**
     * Return {@link PTransform} to emit violations to iprepd
     *
     * @param url URL for iprepd service
     * @return IO transform
     */
    public static Write write(String url) {
        return new Write(url);
    }

    /**
     * Write violation messages to iprepd based on submitted {@link Result} JSON strings
     *
     * <p>For each JSON string processed, an attempt will be made to convert the {@link Result}
     * into a {@link Violation}, for any successful conversion the resulting violation will be
     * submitted to iprepd as a violation message for the source address. Any input data that is
     * not a {@link Result} will be ignored.
     */
    public static class Write extends PTransform<PCollection<String>, PDone> {
        private static final long serialVersionUID = 1L;
        private final String url;

        public Write(String url) {
            this.url = url;
        }

        public String getURL() {
            return url;
        }

        @Override
        public PDone expand(PCollection<String> input) {
            input.apply(ParDo.of(new WriteFn(this)));
            return PDone.in(input.getPipeline());
        }
    }

    private static class WriteFn extends DoFn<String, Void> {
        private static final long serialVersionUID = 1L;

        private final Write wTransform;
        private Logger log;
        private HttpClient httpClient;

        public WriteFn(Write wTransform) {
            this.wTransform = wTransform;
        }

        @Setup
        public void setup() {
            log = LoggerFactory.getLogger(WriteFn.class);
            log.info("creating new HTTP client for iprepd submission");
            httpClient = HttpClientBuilder.create().build();
        }

        @ProcessElement
        public void processElement(ProcessContext c) throws Exception {
            String el = c.element();

            Result result = Result.fromJSON(el);
            if (result == null) {
                return;
            }

            String sourceAddress = result.getSourceAddress();
            Violation v = result.toViolation();
            if (v == null) {
                return;
            }

            String violationJSON = v.toJSON();
            if (violationJSON == null) {
                return;
            }

            String reqPath = new StringJoiner("/").add(wTransform.getURL())
                .add("violations").add(sourceAddress).toString();
            StringEntity body = new StringEntity(violationJSON);

            log.info("notify iprepd client {} violation {}", sourceAddress, v.getViolation());
            HttpPut put = new HttpPut(reqPath);
            put.addHeader("Content-Type", "application/json");
            put.setEntity(body);
            HttpResponse resp = httpClient.execute(put);
            log.info("PUT to iprepd for {} returned with status code {}", sourceAddress,
                resp.getStatusLine().getStatusCode());
            put.reset();
        }
    }
}
