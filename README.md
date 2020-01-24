# foxsec-pipeline

[![Build Status](https://circleci.com/gh/mozilla-services/foxsec-pipeline/tree/master.svg?style=svg)](https://circleci.com/gh/mozilla-services/foxsec-pipeline/tree/master)
[![Documentation](https://img.shields.io/badge/documentation-link-purple.svg)](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/)

[Apache Beam](https://beam.apache.org/) pipelines for analyzing log data.

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

## Usage

### Pipeline Runtime Secrets

#### Generating locally for use in PipelineOptions

Pipeline runtime secrets can be generated locally using the main method in the `RuntimeSecrets` class.

```bash
bin/m compile exec:java -Dexec.mainClass=com.mozilla.secops.crypto.RuntimeSecrets -Dexec.args='-i testkey -k dataflow -p my-gcp-dataflow-project -r dataflow'
```

Run the class with no options to see usage information. Note that in this case, the key ring name and key name
are being specified as `dataflow`. The existing `RuntimeSecrets` class requires the keys to be accessible
using these identifiers when the pipeline is executing.

The output of the command can be prefixed with `cloudkms://` in an option to enable runtime decryption of the secrets
during pipeline execution.

## Documentation

* [secops-beam Java documentation](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/)

javadoc documentation is currently updated manually and although should be up to date, may not be current
with master.

## Introduction to Beam

To get familiar with developing pipelines in Beam, this repository also contains a small workshop that
provides some guidance on building basic pipelines. The introduction document can be found
[here](docs/beam-intro/INTRO.md).

## Contributing

See the [contributing guidelines](./CONTRIBUTING.md).
