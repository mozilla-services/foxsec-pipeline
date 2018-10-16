package com.mozilla.secops.state;

import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.NoCredentials;

import java.io.IOException;

/**
 * Utilize GCP Datastore for centralized state storage
 */
public class DatastoreStateInterface implements StateInterface {
    private Datastore datastore;
    private KeyFactory keyFactory;
    private final String kind;

    public String getObject(String s) {
        Key nk = keyFactory.newKey(s);
        Entity e = datastore.get(nk);
        if (e == null) {
            return null;
        }
        return e.getString("state");
    }

    public void saveObject(String s, String v) throws StateException {
        Key nk;
        try {
            nk = keyFactory.newKey(s);
        } catch (IllegalArgumentException exc) {
            throw new StateException(exc.getMessage());
        }
        Entity.Builder eb = Entity.newBuilder(nk);
        eb.set("state", v);
        Entity e = eb.build();
        Boolean tryAdd = false;
        try {
            datastore.update(e);
        } catch (DatastoreException exc) {
            // https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
            // GRPC NOT_FOUND
            if (exc.getCode() != 5) {
                throw exc;
            } else {
                tryAdd = true;
            }
        }
        if (tryAdd) {
            try {
                datastore.add(e);
            } catch (DatastoreException exc) {
                throw new StateException(exc.getMessage());
            }
        }
    }

    public void done() {
    }

    public void initialize() throws StateException {
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

    /**
     * Initialize a Datastore state interface
     *
     * @param kind kind value to use for stored objects
     */
    public DatastoreStateInterface(String kind) {
        this.kind = kind;
    }
}
