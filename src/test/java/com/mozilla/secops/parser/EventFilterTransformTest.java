package com.mozilla.secops.parser;

import org.junit.Test;
import org.junit.Rule;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.KV;

public class EventFilterTransformTest {
    public EventFilterTransformTest() {
    }

    @Rule public final transient TestPipeline pipeline = TestPipeline.create();

    @Test
    public void testTransformPayloadMatch() throws Exception {
        Parser p = new Parser();
        Event e = p.parse("picard");
        assertNotNull(e);
        PCollection<Event> input = pipeline.apply(Create.of(e));

        EventFilter pFilter = new EventFilter();
        assertNotNull(pFilter);
        pFilter.wantSubtype(Payload.PayloadType.RAW);

        EventFilter nFilter = new EventFilter();
        assertNotNull(nFilter);
        nFilter.wantSubtype(Payload.PayloadType.GLB);

        PCollection<Event> pfiltered = input.apply("positive", EventFilter.getTransform(pFilter));
        PCollection<Event> nfiltered = input.apply("negative", EventFilter.getTransform(nFilter));

        PCollection<Long> pcount = pfiltered.apply("pcount", Count.globally());
        PAssert.that(pcount).containsInAnyOrder(1L);

        PCollection<Long> ncount = nfiltered.apply("ncount", Count.globally());
        PAssert.that(ncount).containsInAnyOrder(0L);

        pipeline.run().waitUntilFinish();
    }
}
