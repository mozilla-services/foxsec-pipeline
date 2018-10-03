#!/bin/bash

set -e

gcloud config set project foxsec-pipeline
nohup gcloud beta emulators datastore start >/dev/null 2>&1 &

/usr/bin/memcached -u root -d

while ! nc -z localhost 8081; do sleep 0.1; done

exec "$@"
