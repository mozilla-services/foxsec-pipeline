package com.mozilla.secops.hhfixed;

import org.junit.Test;
import org.junit.Rule;

import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.KV;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Scanner;
import java.util.ArrayList;

public class HeavyHittersTest {
    public HeavyHittersTest() {
    }

    @Rule public final transient TestPipeline p = TestPipeline.create();

    @Test
    public void noopPipelineTest() throws Exception {
        p.run().waitUntilFinish();
    }

    @Test
    public void countRequestsTest() throws Exception {
        ArrayList<KV<String,Long>> expected = new ArrayList<KV<String,Long>>();
        expected.add(KV.of("127.0.0.1", 50L));
        expected.add(KV.of("127.0.0.2", 10L));

        ArrayList<String> a = new ArrayList<String>();
        InputStream in = getClass().getResourceAsStream("/testdata/hhfixed-simple1.txt");
        Scanner s = new Scanner(in);
        while (s.hasNext()) {
            a.add(s.next());
        }
        s.close();

        PCollection<String> input = p.apply(Create.of(a));
        PCollection<KV<String,Long>> cnt = input.apply(ParDo.of(new HeavyHitters.ParseFn()))
            .apply(Count.<String>perElement());

        PAssert.that(cnt).containsInAnyOrder(expected);

        p.run().waitUntilFinish();
    }
}
