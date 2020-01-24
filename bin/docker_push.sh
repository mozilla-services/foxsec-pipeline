#!/bin/bash

tag="latest"
if [[ -n "$CIRCLE_TAG" ]]; then
	tag=$CIRCLE_TAG
fi

docker tag foxsec-pipeline:latest mozilla/foxsec-pipeline:${tag}

docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"

docker push mozilla/foxsec-pipeline:${tag}
