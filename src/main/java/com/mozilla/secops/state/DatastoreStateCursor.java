package com.mozilla.secops.state;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.DatastoreReaderWriter;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.StringValue;
import com.google.cloud.datastore.Transaction;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;

/** Datastore state cursor implementation */
public class DatastoreStateCursor<T> extends StateCursor<T> {
  private DatastoreReaderWriter rw;
  private Datastore datastore;
  private String namespace;
  private String kind;
  private KeyFactory keyFactory;
  private Transaction tx;

  /**
   * Commit datastore transaction
   *
   * @throws StateException
   */
  public void commit() throws StateException {
    if (tx == null) {
      throw new StateException("datastore cursor not configured as transaction");
    }
    try {
      tx.commit();
    } catch (DatastoreException exc) {
      throw new StateException(exc.getMessage());
    } finally {
      if (tx.isActive()) {
        tx.rollback();
      }
    }
  }

  @Override
  public void executeInner() throws StateException {
    ArrayList<StateOperation<T>> getOperations = new ArrayList<>();
    ArrayList<Key> getParam = new ArrayList<>();

    ArrayList<StateOperation<T>> setOperations = new ArrayList<>();
    ArrayList<Entity> setParam = new ArrayList<>();

    ArrayList<StateOperation<T>> getAllOperations = new ArrayList<>();

    // Batch the various operations based on the type
    for (StateOperation<T> o : operations) {
      switch (o.getOperationType()) {
        case GET:
          getParam.add(keyFactory.newKey(o.getKey()));
          getOperations.add(o);
          break;
        case SET:
          Key nk = keyFactory.newKey(o.getKey());
          Entity.Builder eb = Entity.newBuilder(nk);
          try {
            StringValue sv =
                StringValue.newBuilder(mapper.writeValueAsString(o.getValue()))
                    .setExcludeFromIndexes(true)
                    .build();
            eb.set("state", sv);
          } catch (JsonProcessingException exc) {
            throw new StateException(exc.getMessage());
          }
          setParam.add(eb.build());
          setOperations.add(o);
          break;
        case GET_ALL:
          getAllOperations.add(o);
          break;
        default:
          throw new RuntimeException("unknown operation type");
      }
    }

    Entity[] setParamFinal = setParam.toArray(new Entity[0]);
    Key[] getParamFinal = getParam.toArray(new Key[0]);

    Iterator<Entity> getResults = null;
    try {
      getResults = rw.get(getParamFinal);
      rw.put(setParamFinal);
    } catch (DatastoreException exc) {
      throw new StateException(exc.getMessage());
    }

    for (StateOperation<T> o : getAllOperations) {
      ArrayList<T> vlist = new ArrayList<>();
      Query<Entity> query =
          Query.newEntityQueryBuilder().setNamespace(namespace).setKind(kind).build();
      QueryResults<Entity> results = rw.run(query);
      while (results.hasNext()) {
        Entity e = results.next();
        String buf = e.getString("state");
        try {
          vlist.add(mapper.readValue(buf, stateClass));
        } catch (IOException exc) {
          throw new StateException(exc.getMessage());
        }
      }
      o.setResultValues(vlist);
      completedOperations.put(o.getId(), o);
    }

    // Assemble the get results as completed operations
    ArrayList<String> foundKeys = new ArrayList<>();
    while (getResults.hasNext()) {
      Entity e = getResults.next();
      for (StateOperation<T> o : getOperations) {
        if (o.getKey().equals(e.getKey().getName())) {
          foundKeys.add(o.getKey());
          String buf = e.getString("state");
          try {
            o.setResultValue(mapper.readValue(buf, stateClass));
            completedOperations.put(o.getId(), o);
          } catch (IOException exc) {
            throw new StateException(exc.getMessage());
          }
        }
      }
    }

    // We are done with the query, so iterate again and for any key we didn't see, mark
    // the operation as complete but maintain a null result value to indicate it wasn't
    // found.
    for (StateOperation<T> o : getOperations) {
      if (!foundKeys.contains(o.getKey())) {
        completedOperations.put(o.getId(), o);
      }
    }
  }

  /**
   * Initialize a new Datastore cursor
   *
   * @param d Initialized {@link Datastore} object
   * @param namespace Datastore namespace
   * @param kind Datastore kind
   * @param stateClass Class used in stage storage
   * @param transaction True to initialize cursor as a transaction
   */
  public DatastoreStateCursor(
      Datastore d, String namespace, String kind, Class<T> stateClass, boolean transaction) {
    super(stateClass);
    rw = datastore = d;
    this.namespace = namespace;
    this.kind = kind;
    tx = null;
    if (transaction) {
      rw = tx = d.newTransaction();
    }
    keyFactory = d.newKeyFactory().setNamespace(namespace).setKind(kind);
  }
}
