module github.com/mozilla-services/foxsec-pipeline/contrib/slackbot-http

require (
	cloud.google.com/go/pubsub v1.27.1
	github.com/gorilla/websocket v1.4.0 // indirect
	github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0
	github.com/nlopes/slack v0.6.0
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.8.1
	go.mozilla.org/mozlogrus v2.0.0+incompatible
	google.golang.org/grpc v1.53.0 // indirect
)

replace github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0 => ../

go 1.13
