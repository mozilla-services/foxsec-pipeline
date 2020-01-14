package com.mozilla.secops.state;

import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.StringValue;
import com.google.cloud.datastore.Transaction;
import java.util.ArrayList;
import java.util.List;

/** Datastore state cursor implementation */
public class DatastoreStateCursor extends StateCursor {
  private Datastore datastore;
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

  public String getObject(String s) throws StateException {
    try {
      Key nk = keyFactory.newKey(s);
      Entity e = tx.get(nk);
      if (e == null) {
        return null;
      }
      return e.getString("state");
    } catch (DatastoreException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  public String[] getAllObjects() throws StateException {
    try {
      Query<Entity> query =
          Query.newEntityQueryBuilder().setNamespace(namespace).setKind(kind).build();
      QueryResults<Entity> results = datastore.run(query);
      if (results == null) {
        return null;
      }
      List<String> entities = new ArrayList<String>();
      while (results.hasNext()) {
        Entity e = results.next();
        entities.add(e.getString("state"));
      }
      String[] arr = new String[entities.size()];
      return entities.toArray(arr);
    } catch (DatastoreException exc) {
      throw new StateException(exc.getMessage());
    }
  }

  public void saveObject(String s, String v) throws StateException {
    Key nk;
    try {
      nk = keyFactory.newKey(s);
    } catch (IllegalArgumentException exc) {
      throw new StateException(exc.getMessage());
    }
    Entity.Builder eb = Entity.newBuilder(nk);
    StringValue value = StringValue.newBuilder(v).setExcludeFromIndexes(true).build();
    eb.set("state", value);
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
    this.datastore = d;
    this.namespace = namespace;
    this.kind = kind;
    keyFactory = d.newKeyFactory().setNamespace(namespace).setKind(kind);
    tx = d.newTransaction();
  }
}
