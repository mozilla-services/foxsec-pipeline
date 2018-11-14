package com.mozilla.secops.alert;

import org.apache.beam.sdk.transforms.DoFn;

/**
 * {@link DoFn} for conversion of {@link Alert} objects into JSON strings
 */
public class AlertFormatter extends DoFn<Alert, String> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void processElement(ProcessContext c) {
        c.output(c.element().toJSON());
    }
}
