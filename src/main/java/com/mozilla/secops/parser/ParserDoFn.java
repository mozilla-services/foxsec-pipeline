package com.mozilla.secops.parser;

import org.apache.beam.sdk.transforms.DoFn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Parser;

/**
 * {@link DoFn} applying simple event parsing operations
 */
public class ParserDoFn extends DoFn<String, Event> {
    private static final long serialVersionUID = 1L;

    private Logger log;
    private Parser ep;
    private Long parseCount;

    @Setup
    public void setup() {
        ep = new Parser();
        log = LoggerFactory.getLogger(ParserDoFn.class);
        log.info("initialized new parser");
    }

    @StartBundle
    public void StartBundle() {
        log.info("processing new bundle");
        parseCount = 0L;
    }

    @FinishBundle
    public void FinishBundle() {
        log.info("{} events processed in bundle", parseCount);
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
        Event e = ep.parse(c.element());
        if (e != null) {
            parseCount++;
            c.output(e);
        }
    }
}
