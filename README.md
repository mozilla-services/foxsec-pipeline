# foxsec-pipeline

[![Build Status](https://travis-ci.org/mozilla-services/foxsec-pipeline.svg?branch=master)](https://travis-ci.org/mozilla-services/foxsec-pipeline)

[Apache Beam](https://beam.apache.org/) pipelines for analyzing log data.

## Tests

Tests can be executed locally using Docker.

### Run all tests

```bash
docker build -t foxsec-pipeline:latest .
bin/m test
```

### Run a specific test

```bash
docker build -t foxsec-pipeline:latest .
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

## Contributing

See the [contributing guidelines](./CONTRIBUTING.md).
