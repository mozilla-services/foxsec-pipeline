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
