package com.mozilla.secops.state;

import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Transaction;

/** Datastore state cursor implementation */
public class DatastoreStateCursor extends StateCursor {
  private String namespace;
  private String kind;
  private KeyFactory keyFactory;
  private Transaction tx;

  public void commit() throws StateException {
    try {
      tx.commit();
    } catch (DatastoreException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  public String getObject(String s) {
    Key nk = keyFactory.newKey(s);
    Entity e = tx.get(nk);
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
    try {
      tx.put(e);
    } catch (DatastoreException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  /**
   * Initialize a new Datastore cursor
   *
   * @param d Initialized {@link Datastore} object
   */
  public DatastoreStateCursor(Datastore d, String namespace, String kind) {
    this.namespace = namespace;
    this.kind = kind;
    keyFactory = d.newKeyFactory().setNamespace(namespace).setKind(kind);
    tx = d.newTransaction();
  }
}
