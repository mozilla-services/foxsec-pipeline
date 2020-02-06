package main

import (
	"context"

	"github.com/mozilla-services/foxsec-pipeline-contrib/duopull"
)

func main() {
	pbmsg := duopull.PubSubMessage{}
	duopull.Duopull(context.Background(), pbmsg)
}
