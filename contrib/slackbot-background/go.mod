module github.com/mozilla-services/foxsec-pipeline/contrib/slackbot-background

require (
	cloud.google.com/go v0.36.0
	github.com/gorilla/websocket v1.4.0 // indirect
	github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0
	github.com/nlopes/slack v0.6.0
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.3.0
	go.mozilla.org/mozlogrus v2.0.0+incompatible
)

replace github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0 => ../

go 1.16
