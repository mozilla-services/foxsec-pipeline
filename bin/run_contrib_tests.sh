#!/bin/bash

# Execute contrib/ tests, assumes it is being run within the pipeline
# docker image. For a helper script to execute this in a docker container
# from the host environment see bin/c.

set -e

cd /root/project/contrib
go test -v ./...
(cd auth0pull && go test -v)
(cd cloudtrail-streamer && go test -v)
(cd duopull && go test -v)
(cd slackbot-background && go test -v)
(cd slackbot-http && go test -v)
