module github.com/mozilla-services/foxsec-pipeline-contrib/duopull/cmd

go 1.12

require (
	github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0
	github.com/mozilla-services/foxsec-pipeline-contrib/duopull v0.0.0
)

replace github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0 => ../../

replace github.com/mozilla-services/foxsec-pipeline-contrib/duopull v0.0.0 => ../
