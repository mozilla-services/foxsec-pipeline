FROM golang:1.12-stretch

RUN export CLOUD_SDK_REPO="cloud-sdk-stretch" && \
    echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    apt-get update -y && apt-get install google-cloud-sdk -y

RUN apt-get install google-cloud-sdk-datastore-emulator net-tools netcat -y

COPY . /go/src/github.com/mozilla-services/foxsec-pipeline-contrib
RUN cd /go/src/github.com/mozilla-services/foxsec-pipeline-contrib && \
    GO111MODULE=on GOPROXY=https://proxy.golang.org go get ./...

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
