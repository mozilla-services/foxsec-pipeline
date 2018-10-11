package com.mozilla.secops.httprequest;

import org.junit.Test;
import org.junit.Rule;
import static org.junit.Assert.assertEquals;

import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.KV;

import org.joda.time.Instant;

import com.mozilla.secops.parser.Event;

import java.io.IOException;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

public class TestThresholdAnalysis1 {
    public TestThresholdAnalysis1() {
    }

    private PCollection<String> getInput() throws IOException {
        ArrayList<String> inputData = new ArrayList<String>();
        GZIPInputStream in = new GZIPInputStream(getClass()
                .getResourceAsStream("/testdata/httpreq_thresholdanalysis1.txt.gz"));
        Scanner scanner = new Scanner(in);
        while (scanner.hasNextLine()) {
            inputData.add(scanner.nextLine());
        }
        scanner.close();
        return p.apply(Create.of(inputData));
    }

    @Rule public final transient TestPipeline p = TestPipeline.create();

    @Test
    public void noopPipelineTest() throws Exception {
        p.run().waitUntilFinish();
    }

    @Test
    public void countRequestsTest() throws Exception {
        PCollection<String> input = getInput();

        PCollection<Event> events = input.apply(new HTTPRequest.ParseAndWindow());
        PCollection<Long> count = events.apply(Combine.globally(Count.<Event>combineFn())
                .withoutDefaults());

        PAssert.that(count)
            .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
            .containsInAnyOrder(2400L);
        PAssert.that(count)
            .inWindow(new IntervalWindow(new Instant(300000L), new Instant(360000)))
            .containsInAnyOrder(2520L);

        p.run().waitUntilFinish();
    }

    @Test
    public void countInWindowTest() throws Exception {
        ArrayList<KV<String, Long>> expect = new ArrayList<KV<String, Long>>(Arrays.asList(
                KV.of("192.168.1.1", 60L),
                KV.of("192.168.1.2", 60L),
                KV.of("192.168.1.3", 60L),
                KV.of("192.168.1.4", 60L),
                KV.of("192.168.1.5", 60L),
                KV.of("192.168.1.6", 60L),
                KV.of("192.168.1.7", 60L),
                KV.of("192.168.1.8", 60L),
                KV.of("192.168.1.9", 60L),
                KV.of("192.168.1.10", 60L),
                KV.of("10.0.0.1", 900L),
                KV.of("10.0.0.2", 900L)
            ));
        PCollection<String> input = getInput();

        PCollection<KV<String, Long>> counts = input.apply(new HTTPRequest.ParseAndWindow())
            .apply(new HTTPRequest.CountInWindow());

        PAssert.that(counts)
            .inWindow(new IntervalWindow(new Instant(0L), new Instant(60000)))
            .containsInAnyOrder(expect);

        p.run().waitUntilFinish();
    }
}
