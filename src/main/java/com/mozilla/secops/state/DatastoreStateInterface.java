package com.mozilla.secops.state;

import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.IncompleteKey;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.FullEntity;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.datastore.DatastoreException;

import java.io.FileInputStream;
import java.io.IOException;

public class DatastoreStateInterface implements StateInterface {
    private Datastore datastore;
    private KeyFactory keyFactory;

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

    public DatastoreStateInterface(String kind) {
        datastore = DatastoreOptions.getDefaultInstance().getService();
        keyFactory = datastore.newKeyFactory().setKind(kind);
    }

    public DatastoreStateInterface(String kind, String sfpath) throws IOException {
        datastore = DatastoreOptions.newBuilder().setCredentials(
                ServiceAccountCredentials.fromStream(new FileInputStream(sfpath)))
            .build().getService();
        keyFactory = datastore.newKeyFactory().setKind(kind);
    }
}
