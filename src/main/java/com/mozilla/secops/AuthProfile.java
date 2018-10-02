package com.mozilla.secops;

import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.options.Validation.Required;
import org.apache.beam.sdk.options.ValueProvider;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.transforms.windowing.TimestampCombiner;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.GlobalWindows;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.KV;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.Duration;
import org.joda.time.Instant;

import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.OpenSSH;
import com.mozilla.secops.parser.Parser;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.userspec.UserSpec;

import java.io.IOException;
import java.lang.IllegalArgumentException;

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

class StateModel {
    private String identity;
    private Map<String,ModelEntry> entries;

    private long pruneAge;

    static class ModelEntry {
        private DateTime timestamp;

        public DateTime getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(DateTime ts) {
            timestamp = ts;
        }

        @JsonCreator
        ModelEntry(@JsonProperty("timestamp") DateTime ts) {
            timestamp = ts;
        }
    }

    public Boolean knownAddress(String address) {
        return entries.get(address) != null;
    }

    public Map<String,ModelEntry> getEntries() {
        return entries;
    }

    public String getIdentity() {
        return identity;
    }

    private void pruneOldEntries() {
        Iterator it = entries.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry p = (Map.Entry)it.next();
            ModelEntry me = (ModelEntry)p.getValue();
            long mts = me.getTimestamp().getMillis() / 1000;
            if ((DateTimeUtils.currentTimeMillis() / 1000) - mts > pruneAge) {
                it.remove();
            }
        }
    }

    public Boolean updateModel(String address, DateTime ts) {
        pruneOldEntries();
        Boolean isNew = false;
        ModelEntry newent = new ModelEntry(ts);
        if (entries.get(address) == null) {
            isNew = true;
        }
        entries.put(address, newent);
        return isNew;
    }

    @JsonCreator
    StateModel(@JsonProperty("identity") String user) {
        identity = user;
        entries = new HashMap<String,ModelEntry>();
        pruneAge = 60 * 60 * 24 * 10; // Default 10 days for prune age
    }
}

class ParseFn extends DoFn<String,KV<String,Event>> {
    private Parser ep;

    ParseFn() {
    }

    @Setup
    public void Setup() {
        ep = new Parser();
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
        System.out.println(c.element());
        Event e = ep.parse(c.element());
        Normalized n = e.getNormalized();
        if (n.getType() == Normalized.Type.AUTH) {
            //c.output(KV.of(n.getSubjectUser(), e));
            System.out.println(new Instant());
            c.outputWithTimestamp(KV.of(n.getSubjectUser(), e), new Instant());
        }
    }
}

class AnalyzeFn extends DoFn<KV<String,Iterable<Event>>,String> {
    private final Logger log;
    private State state;
    private Boolean initialized;
    private ValueProvider<String> memcachedHost;
    private ValueProvider<String> datastoreKind;

    AnalyzeFn(ValueProvider<String> mch, ValueProvider<String> dsk) {
        log = LoggerFactory.getLogger(AnalyzeFn.class);
        memcachedHost = mch;
        datastoreKind = dsk;
    }

    @Setup
    public void Setup() throws IOException, IllegalArgumentException {
        System.out.println("IN SETUP");
        if (memcachedHost.isAccessible() && memcachedHost.get() != null) {
            String mch = memcachedHost.get();
            log.info("Initializing memcached state connection to {}", mch);
            state = new State(new MemcachedStateInterface(mch));
        } else if (datastoreKind.isAccessible() && datastoreKind.get() != null) {
            System.out.println("CONFIGURE DATASTORE");
            String dsk = datastoreKind.get();
            log.info("Initializing datastore state for {}", dsk);
            state = new State(new DatastoreStateInterface(dsk));
        } else {
            throw new IllegalArgumentException("no state mechanism specified");
        }
    }

    @Teardown
    public void Teardown() {
        state.done();
    }

    @ProcessElement
    public void processElement(ProcessContext c) throws IOException {
        System.out.println(c.element());
        Iterable<Event> events = c.element().getValue();
        String u = c.element().getKey();
        for (Event e : events) {
            Normalized n = e.getNormalized();
            String address = n.getSourceAddress();
            StateModel sm = null;

            Boolean willCreate = false;
            sm = state.get(u, StateModel.class);
            if (sm == null) {
                log.info("State model for {} not found, will create", u);
                willCreate = true;
            }

            if (willCreate) {
                sm = new StateModel(u);
                sm.updateModel(address, new DateTime());
                state.set(u, sm);
                continue;
            }

            Boolean isNew = sm.updateModel(address, new DateTime());
            if (!isNew) {
                continue;
            }
            log.info("New model entry for {}, {}", u, address);
        }
    }
}

public class AuthProfile {
    public interface AuthProfileOptions extends PipelineOptions {
        @Description("Read input from file path")
        String getInputFile();
        void setInputFile(String value);

        @Description("Read input from pubsub topic")
        String getInputPubsub();
        void setInputPubsub(String value);

        @Description("Read user specification from file path")
        String getUserSpecPath();
        void setUserSpecPath(String value);

        @Description("Use memcached host for state")
        ValueProvider<String> getMemcachedHost();
        void setMemcachedHost(ValueProvider<String> value);

        @Description("Use datastore storage with kind")
        ValueProvider<String> getDatastoreKind();
        void setDatastoreKind(ValueProvider<String> value);
    }

    static void runAuthProfile(AuthProfileOptions options) throws Exception {
        final Logger log = LoggerFactory.getLogger(AuthProfile.class);
        log.info("Initializing pipeline");
        Pipeline p = Pipeline.create(options);

        PCollection<String> input;
        if (options.getInputFile() != null) {
            input = p.apply(TextIO.read().from(options.getInputFile()));
        } else if (options.getInputPubsub() != null) {
            input = p.apply(PubsubIO.readStrings()
                    .fromTopic(options.getInputPubsub()));
        } else {
            throw new IllegalArgumentException("no valid input specified");
        }

        PCollection<KV<String,Iterable<Event>>> mevent = input.apply(ParDo.of(new ParseFn()))
            .apply(Window.<KV<String,Event>>into(new GlobalWindows())
                    .triggering(Repeatedly
                        .forever(AfterProcessingTime
                            .pastFirstElementInPane()
                            .plusDelayOf(Duration.standardSeconds(30))))
                    .withAllowedLateness(Duration.standardSeconds(30)).discardingFiredPanes())
            .apply(GroupByKey.<String,Event>create());

        System.out.println("ANALYZE");
        /*if (options.getMemcachedHost() != null) {
            System.out.println("USING MEMCACHED");
            mevent.apply(ParDo.of(new AnalyzeFn(options.getMemcachedHost(), options.getDatastoreKind())));*/
        if (options.getDatastoreKind() != null) {
            System.out.println("USING DATASTORE");
            mevent.apply(ParDo.of(new AnalyzeFn(options.getMemcachedHost(), options.getDatastoreKind())));
        } else {
            throw new IllegalArgumentException("no valid state method specified");
        }

        //p.run().waitUntilFinish();
        p.run();
    }

    public static void main(String[] args) throws Exception {
        AuthProfileOptions options =
            PipelineOptionsFactory.fromArgs(args).withValidation().as(AuthProfileOptions.class);
        runAuthProfile(options);
    }
}
