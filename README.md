# foxsec-pipeline

[![Build Status](https://travis-ci.org/mozilla-services/foxsec-pipeline.svg?branch=master)](https://travis-ci.org/mozilla-services/foxsec-pipeline)
[![Documentation](https://img.shields.io/badge/documentation-link-purple.svg)](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/)

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

## Documentation

* [secops-beam Java documentation](https://mozilla-services.github.io/foxsec-pipeline/secops-beam/)

javadoc documentation is currently updated manually and although should be up to date, may not be current
with master.

## Introduction to Beam

To get familiar with developing pipelines in Beam, this repository also contains a small workshop that
provides some guidance on building basic pipelines. The introduction document can be found
[here](docs/beam-intro/INTRO.md).

## Pipeline Options and Arguments

To run a pipeline compile the Maven project and run the entrypoint class (containing main):

```
mvn compile exec:java -Dexec.mainClass={PIPELINE_ENTRYPOINT_CLASS}
```

Depending on the type of input from which you wish to feed data to a Beam pipeline, you will need to provide input-specific arguments to the java program. This is done with Maven's "-Dexec.args" command line flag as follows (with closing single quotes):

```
-Dexec.args='--argument1={ARG_VALUE} --argument2=${ARG_VALUE}'
```

#### All use cases:

* The following argument is mandatory for all input options:

```
--monitoredResourceIndicator=${PIPELINE_DESCRIPTION}
```

#### Data From File:

* Each line in the file will be received as a distinct element to be parsed and processed in the pipeline

```
--inputFile={PATH_TO_INPUT_FILE}
```

#### Data From AWS Kinesis Stream:

* Each entry in the Kinesis stream will be received as a distinct element to be parsed and processed in the pipeline

```
--inputKinesis={KINESIS_STREAM_NAME}:{AWS_ACCESS_KEY_ID}:{AWS_SECRET_ACCESS_KEY}:{AWS_REGION}
```

#### Data From GCP Pub/Sub Topic:

* If no arguments are provided, the program will attempt to use the host machine's gcloud default configuration (typically found in ```~/.config/gcloud/configurations/config_default```) 

* Each message in the topic will be received as a distinct element to be parsed and processed in the pipeline

```
--inputPubsub={PUB_SUB_TOPIC_NAME} --project={GCP_PROJECT_NAME}
```

## Contributing

See the [contributing guidelines](./CONTRIBUTING.md).
