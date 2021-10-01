package main

import (
	"context"

	"github.com/mozilla-services/foxsec-pipeline/contrib/papertrailpull"
)

func main() {
	err := papertrailpull.PapertrailPull(context.Background(), papertrailpull.PubSubMessage{})
	if err != nil {
		panic(err)
	}
}
