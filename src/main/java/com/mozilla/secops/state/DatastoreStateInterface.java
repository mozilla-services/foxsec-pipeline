package com.mozilla.secops.state;

import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.NoCredentials;

import java.io.IOException;

public class DatastoreStateInterface implements StateInterface {
    private Datastore datastore;
    private KeyFactory keyFactory;
    private String kind;

    public String getObject(String s) {
        Key nk = keyFactory.newKey(s);
        Entity e = datastore.get(nk);
        if (e == null) {
            return null;
        }
        return e.getString("state");
    }

    public void saveObject(String s, String v) {
        Key nk = keyFactory.newKey(s);
        Entity.Builder eb = Entity.newBuilder(nk);
        eb.set("state", v);
        Entity e = eb.build();
        Boolean tryAdd = false;
        try {
            datastore.update(e);
        } catch (DatastoreException exc) {
            tryAdd = true;
        }
        if (!tryAdd) {
            return;
        }
        datastore.add(e);
    }

    public void done() {
    }

    public void initialize() throws IOException {
        String emulatorHost = System.getenv("DATASTORE_HOST");
        String emulatorProject = System.getenv("DATASTORE_PROJECT_ID");

        if (emulatorHost != null && emulatorProject != null) {
            DatastoreOptions.Builder b = DatastoreOptions.newBuilder();
            b.setHost(emulatorHost);
            b.setProjectId(emulatorProject);
            b.setCredentials(NoCredentials.getInstance());
            datastore = b.build().getService();
        } else {
            datastore = DatastoreOptions.getDefaultInstance().getService();
        }
        keyFactory = datastore.newKeyFactory().setKind(kind);
    }

    public DatastoreStateInterface(String kind) {
        this.kind = kind;
    }
}
