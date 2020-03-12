module github.com/mozilla-services/foxsec-pipeline/contrib/bugzilla-alert-manager

go 1.14

require (
	cloud.google.com/go v0.54.0
	cloud.google.com/go/pubsub v1.3.0
	github.com/PagerDuty/go-pagerduty v1.1.3-0.20200307000252-c2d5dcd0d508
	github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	go.mozilla.org/mozlogrus v2.0.0+incompatible
)

replace github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0 => ../
