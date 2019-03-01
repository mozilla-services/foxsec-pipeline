package com.mozilla.secops.state;

import com.google.cloud.NoCredentials;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.StructuredQuery;

/** Utilize GCP Datastore for centralized state storage */
public class DatastoreStateInterface implements StateInterface {
  private Datastore datastore;
  private KeyFactory keyFactory;
  private final String kind;
  private final String namespace;
  private String project;

  public void deleteAll() throws StateException {
    StructuredQuery<Entity> query =
        Query.newEntityQueryBuilder().setNamespace(namespace).setKind(kind).build();
    QueryResults<Entity> results = datastore.run(query);

    while (results.hasNext()) {
      datastore.delete(results.next().getKey());
    }
  }

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

  public void done() {}

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
      DatastoreOptions.Builder b = DatastoreOptions.getDefaultInstance().toBuilder();
      if (project != null) {
        b.setProjectId(project);
      }
      datastore = b.build().getService();
    }
    keyFactory = datastore.newKeyFactory().setNamespace(namespace).setKind(kind);
  }

  /**
   * Initialize a Datastore state interface
   *
   * @param kind kind value to use for stored objects
   * @param namespace Datastore namespace
   */
  public DatastoreStateInterface(String kind, String namespace) {
    this.kind = kind;
    this.namespace = namespace;
  }

  /**
   * Initialize a Datastore state interface using datastore in another project
   *
   * @param kind kind value to use for stored objects
   * @param namespace Datastore namespace
   * @param project Project identifier
   */
  public DatastoreStateInterface(String kind, String namespace, String project) {
    this(kind, namespace);
    this.project = project;
  }
}
