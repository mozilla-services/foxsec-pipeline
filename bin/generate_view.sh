#!/bin/bash

# Generate BigQuery metrics view
#
# Called by maven and should not be run directly

f=./target/metrics-view.sql
java com.mozilla.secops.alert.AlertMeta metricsview "${f}"
cat $f
