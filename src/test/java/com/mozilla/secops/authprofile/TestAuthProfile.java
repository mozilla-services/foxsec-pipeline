package com.mozilla.secops.authprofile;

import org.junit.Test;
import org.junit.Rule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.options.PipelineOptionsFactory;

import org.joda.time.Instant;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class TestAuthProfile {
    @Rule
    public final EnvironmentVariables environmentVariables
        = new EnvironmentVariables();

    private void testEnv() {
        environmentVariables.set("DATASTORE_EMULATOR_HOST", "localhost:8081");
        environmentVariables.set("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore");
        environmentVariables.set("DATASTORE_HOST", "http://localhost:8081");
        environmentVariables.set("DATASTORE_PROJECT_ID", "foxsec-pipeline");
    }

    public TestAuthProfile() {
    }

    private PCollection<String> getInput(String resource) {
        ArrayList<String> inputData = new ArrayList<String>();
        InputStream in = TestAuthProfile.class.getResourceAsStream(resource);
        Scanner scanner = new Scanner(in);
        while (scanner.hasNextLine()) {
            inputData.add(scanner.nextLine());
        }
        scanner.close();
        return p.apply(Create.of(inputData));
    }

    private AuthProfile.AuthProfileOptions getTestOptions() {
        AuthProfile.AuthProfileOptions ret =
            PipelineOptionsFactory.as(AuthProfile.AuthProfileOptions.class);
        ret.setDatastoreNamespace("testauthprofileanalyze");
        ret.setDatastoreKind("authprofile");
        return ret;
    }

    @Rule public final transient TestPipeline p = TestPipeline.create();

    @Test
    public void noopPipelineTest() throws Exception {
        p.run().waitUntilFinish();
    }

    @Test
    public void parseAndWindowTest() throws Exception {
        PCollection<String> input = getInput("/testdata/authprof_buffer1.txt");

        PCollection<KV<String, Iterable<Event>>> res = input.apply(new AuthProfile.ParseAndWindow());
        PAssert.thatMap(res).satisfies(
            results -> {
                Iterable<Event> edata = results.get("riker");
                assertNotNull(edata);
                assertTrue(edata instanceof Collection);

                Event[] e = ((Collection<Event>) edata).toArray(new Event[0]);
                assertEquals(e.length, 5);

                Normalized n = e[0].getNormalized();
                assertNotNull(n);
                assertEquals(Normalized.Type.AUTH, n.getType());
                assertEquals("127.0.0.1", n.getSourceAddress());
                assertEquals("riker", n.getSubjectUser());

                return null;
            });

        p.run().waitUntilFinish();
    }

    @Test
    public void analyzeTest() throws Exception {
        testEnv();
        AuthProfile.AuthProfileOptions options = getTestOptions();
        PCollection<String> input = getInput("/testdata/authprof_buffer1.txt");

        PCollection<Alert> res = input.apply(new AuthProfile.ParseAndWindow())
            .apply(ParDo.of(new AuthProfile.Analyze(options)));

        PAssert.that(res).satisfies(
            results -> {
                long newCnt = 0;
                long infoCnt = 0;
                for (Alert a : results) {
                    assertEquals("authprofile", a.getCategory());
                    String actualSummary = a.getSummary();
                    if (actualSummary.equals("riker authenticated to emit-bastion from 127.0.0.1")) {
                        infoCnt++;
                        assertEquals(Alert.AlertSeverity.INFORMATIONAL, a.getSeverity());
                    } else if (actualSummary.equals("riker authenticated to emit-bastion from new source" +
                            ", 127.0.0.1")) {
                        newCnt++;
                        assertEquals(Alert.AlertSeverity.WARNING, a.getSeverity());
                    }
                }
                assertEquals(1L, newCnt);
                assertEquals(4L, infoCnt);
                return null;
            });

        p.run().waitUntilFinish();
    }
}
