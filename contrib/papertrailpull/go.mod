module github.com/mozilla-services/foxsec-pipeline/contrib/papertrailpull

go 1.16

require (
	cloud.google.com/go v0.97.0 // indirect
	cloud.google.com/go/datastore v1.1.0
	cloud.google.com/go/kms v1.0.0 // indirect
	cloud.google.com/go/logging v1.4.2
	github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0
	github.com/sirupsen/logrus v1.4.2
	go.mozilla.org/mozlogrus v2.0.0+incompatible
)

replace github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0 => ../
