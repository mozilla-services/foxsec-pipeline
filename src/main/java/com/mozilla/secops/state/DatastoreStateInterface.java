package com.mozilla.secops.state;

import com.google.cloud.NoCredentials;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreException;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.KeyFactory;
import com.google.cloud.datastore.Query;
import com.google.cloud.datastore.QueryResults;
import com.google.cloud.datastore.StructuredQuery;

/** Utilize GCP Datastore for centralized state storage */
public class DatastoreStateInterface implements StateInterface {
  private Datastore datastore;
  private final String kind;
  private final String namespace;
  private KeyFactory keyFactory;
  private String project;

  public StateCursor newCursor() throws StateException {
    try {
      return new DatastoreStateCursor(datastore, namespace, kind);
    } catch (DatastoreException exc) {
      throw new StateException(exc.getMessage());
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

  public void deleteAll() throws StateException {
    StructuredQuery<Entity> query =
        Query.newEntityQueryBuilder().setNamespace(namespace).setKind(kind).build();
    QueryResults<Entity> results = datastore.run(query);

    while (results.hasNext()) {
      datastore.delete(results.next().getKey());
    }
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
