# foxsec-pipeline

[![Build Status](https://circleci.com/gh/mozilla-services/foxsec-pipeline/tree/master.svg?style=svg)](https://circleci.com/gh/mozilla-services/foxsec-pipeline/tree/master)
[![Documentation](https://img.shields.io/badge/documentation-link-purple.svg)](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/)

## Documentation

* [secops-beam Java documentation](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/)

javadoc documentation is currently updated manually and although should be up to date, may not be current
with master.

## Introduction to Beam

To get familiar with developing pipelines in Beam, this repository also contains a small workshop that
provides some guidance on building basic pipelines. The introduction document can be found
[here](docs/beam-intro/INTRO.md).

## Tests

Tests can be executed locally using Docker.

### Run all tests

```bash
docker build -f Dockerfile-base -t foxsec-pipeline-base:latest .
bin/m test
```

### Run a specific test

```bash
docker build -f Dockerfile-base -t foxsec-pipeline-base:latest .
bin/m test -Dtest=ParserTest
```

## CLI Usage

### Pipeline [RuntimeSecrets](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/com/mozilla/secops/crypto/RuntimeSecrets.html)

Pipeline runtime secrets can be generated locally using the main method in the [`RuntimeSecrets`](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/com/mozilla/secops/crypto/RuntimeSecrets.html) class.

```bash
bin/m compile exec:java -Dexec.mainClass=com.mozilla.secops.crypto.RuntimeSecrets -Dexec.args='-i testkey -k dataflow -p my-gcp-dataflow-project -r dataflow'
```

Run the class with no options to see usage information. Note that in this case, the key ring name and key name
are being specified as `dataflow`. The existing `RuntimeSecrets` class requires the keys to be accessible
using these identifiers when the pipeline is executing.

The output of the command can be prefixed with `cloudkms://` in an option to enable runtime decryption of the secrets
during pipeline execution.

### Interacting with Minfraud

Reputation data can be fetched from Minfraud locally using the main method in the [`Minfraud`](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/com/mozilla/secops/Minfraud.html) class.

You must provide the accountid and licensekey plus the IP and/or email you want to get reputation data for. `--accountid` and `--licensekey` can either be provided directly or provided as RuntimeSecrets (`cloudkms://...`).

```bash
bin/m exec:java \
  -Dexec.mainClass="com.mozilla.secops.Minfraud" \
  -Dexec.args="-p my-gcp-dataflow-project --accountid 'cloudkms://...' --licensekey 'cloudkms://...' --ip '8.8.8.8' --email 'example@example.com'"
```

### Creating Watchlist entries

Watchlist entries can be created locally using the main method in the [`Watchlist`](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/com/mozilla/secops/Watchlist.html) class.

You must also prefix your command with `WITHOUT_DAEMONS=true` so that the entry won't be submitted to the Datastore emulator running within the container.

```
usage: Watchlist
 -c,--createdby <arg>
 -ne,--neverexpires     Watchlist entry never expires (compared to default
                        of 2 weeks)
 -o,--object <arg>      Object to watch. Can be an IP or email.
 -p,--project <arg>     GCP project name (required if submitting to
                        Datastore)
 -s,--severity <arg>    Severity of Watchlist entry. Can be 'info',
                        'warn', or 'crit'
 -su,--submit           Submit Watchlist entry to Datastore rather than
                        emit json
 -t,--type <arg>        Type of object to watch. Can be 'ip' or 'email'
```

#### Example of creating entry without submitting to Datastore
```bash
$ bin/m exec:java -Dexec.mainClass="com.mozilla.secops.Watchlist" -Dexec.args="--object '127.0.0.1' --type 'ip' --createdby 'example@example.com' --severity 'info'"

{"type":"ip","severity":"info","expires_at":"2020-02-26T17:45:01.399Z","created_by":"example@example.com","object":"127.0.0.1"}
```

#### Example of submitting to Datastore
```bash
$ WITHOUT_DAEMONS=true bin/m exec:java -Dexec.mainClass="com.mozilla.secops.Watchlist" -Dexec.args="--object '127.0.0.1' --type 'ip' --createdby 'example@example.com' --severity 'info' --project foxsec-pipeline-nonprod --submit"

Feb 12, 2020 5:41:44 PM com.mozilla.secops.state.State initialize
INFO: Initializing new state interface using com.mozilla.secops.state.DatastoreStateInterface
Feb 12, 2020 5:41:45 PM com.mozilla.secops.state.StateCursor set
INFO: Writing state for 127.0.0.1
Feb 12, 2020 5:41:45 PM com.mozilla.secops.state.State done
INFO: Closing state interface com.mozilla.secops.state.DatastoreStateInterface
Successfully submitted watchlist entry to foxsec-pipeline-nonprod
{"type":"ip","severity":"info","expires_at":"2020-02-26T17:41:43.919Z","created_by":"example@example.com","object":"127.0.0.1"}
```

## Contributing

See the [contributing guidelines](./CONTRIBUTING.md).
