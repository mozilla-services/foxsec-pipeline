package com.mozilla.secops.customs;

import org.junit.Test;
import org.junit.Rule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.transforms.windowing.GlobalWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.options.PipelineOptionsFactory;

import org.joda.time.Instant;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.ParserDoFn;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class TestCustoms {
    @Rule public final transient TestPipeline p = TestPipeline.create();

    public TestCustoms() {
    }

    private PCollection<String> getInput(String resource) {
        ArrayList<String> inputData = new ArrayList<String>();
        InputStream in = TestCustoms.class.getResourceAsStream(resource);
        Scanner scanner = new Scanner(in);
        while (scanner.hasNextLine()) {
            inputData.add(scanner.nextLine());
        }
        scanner.close();
        return p.apply(Create.of(inputData));
    }

    @Test
    public void noopPipelineTest() throws Exception {
        p.run().waitUntilFinish();
    }

    @Test
    public void parseTest() throws Exception {
        PCollection<String> input = getInput("/testdata/customs_rl_badlogin_simple1.txt");

        PCollection<Long> count = input.apply(ParDo.of(new ParserDoFn()))
            .apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

        PAssert.that(count)
            .containsInAnyOrder(447L);

        p.run().waitUntilFinish();
    }

    @Test
    public void rlLoginFailureSourceAddressTest() throws Exception {
        PCollection<String> input = getInput("/testdata/customs_rl_badlogin_simple1.txt");

        PCollection<Alert> alerts = input.apply(ParDo.of(new ParserDoFn()))
            .apply(new Customs.RlLoginFailureSourceAddress(true, 3L, 900L));

        ArrayList<IntervalWindow> windows = new ArrayList<IntervalWindow>();
        windows.add(new IntervalWindow(new Instant(1800000L), new Instant(2700000L)));
        windows.add(new IntervalWindow(new Instant(2700000L), new Instant(3600000L)));
        windows.add(new IntervalWindow(new Instant(11700000L), new Instant(12600000L)));
        windows.add(new IntervalWindow(new Instant(12600000L), new Instant(13500000L)));

        PCollection<Long> count = alerts.apply(
            Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
        PAssert.that(count)
            .satisfies(
                x -> {
                    int cnt = 0;
                    for (Long l : x) {
                        cnt += l;
                    }
                    assertEquals(4L, cnt);
                    return null;
                }
            );

        for (IntervalWindow w : windows) {
            PAssert.that(alerts)
                .inWindow(w)
                .satisfies(
                    x -> {
                        int cnt = 0;
                        for (Alert a : x) {
                            assertEquals("customs", a.getCategory());
                            assertEquals("127.0.0.1", a.getMetadataValue("customs_suspected"));
                            cnt++;
                        }
                        assertEquals(1, cnt);
                        return null;
                    }
                );
        }

        p.run().waitUntilFinish();
    }
}
