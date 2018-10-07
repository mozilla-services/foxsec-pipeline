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

import org.joda.time.Instant;

import com.mozilla.secops.parser.Event;

import java.util.Scanner;
import java.util.ArrayList;
import java.util.zip.GZIPInputStream;

public class HTTPRequestTest {
    public HTTPRequestTest() {
    }

    @Rule public final transient TestPipeline p = TestPipeline.create();

    @Test
    public void noopPipelineTest() throws Exception {
        p.run().waitUntilFinish();
    }

    @Test
    public void countRequestsTest() throws Exception {
        ArrayList<String> inputData = new ArrayList<String>();
        GZIPInputStream in = new GZIPInputStream(getClass()
                .getResourceAsStream("/testdata/heavyhitters1.txt.gz"));
        Scanner scanner = new Scanner(in);
        while (scanner.hasNextLine()) {
            inputData.add(scanner.nextLine());
        }
        scanner.close();
        PCollection<String> input = p.apply(Create.of(inputData));

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
}
