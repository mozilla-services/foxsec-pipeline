#!/bin/bash

# Convert existing Java alert metadata into Golang constants
#
# Called by maven and should not be run directly

f=`mktemp`
outpath=contrib/common/alertmeta.go

java com.mozilla.secops.alert.AlertMeta gometa "${f}"
gofmt $f > $outpath
