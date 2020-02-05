#!/bin/bash

docker run -it --rm \
  -v $PWD:/go/src/github.com/mozilla-services/foxsec-pipeline-contrib \
  foxsec-pipeline-contrib:latest \
  bash -c "go test ./...; cd duopull/; go test; cd ..; cd slackbot-background; go test"
