all: build

# Package lambda function in zip file
package:
	docker run -i --rm -v `pwd`:/go/src/github.com/mozilla-services/cloudtrail-streamer -e CGO_ENABLED=0\
		golang:1.13 \
		/bin/bash -c 'cd /go/src/github.com/mozilla-services/cloudtrail-streamer && make docker_build'

# Development target, upload package to s3
packageupload:
	@if [[ -z "$(CT_DEV_S3_BUCKET)" ]]; then \
		echo "set CT_DEV_S3_BUCKET in environment"; \
		exit 1; \
	fi
	aws s3 cp cloudtrail-streamer.zip s3://$(CT_DEV_S3_BUCKET)/cloudtrail-streamer.zip

docker_build: clean build
	apt-get update
	apt-get install -y zip
	zip cloudtrail-streamer.zip cloudtrail-streamer
	zip -r cloudtrail-streamer.zip gcp_credentials.json || true

local_build: clean build
	zip cloudtrail-streamer.zip cloudtrail-streamer
	zip -r cloudtrail-streamer.zip gcp_credentials.json || true

clean:
	rm -f cloudtrail-streamer cloudtrail-streamer.zip

build:
	go build -ldflags="-s -w" -o cloudtrail-streamer

debug: build
	env CT_DEBUG_LOGGING=1 ./cloudtrail-streamer

test:
	go test ./...
