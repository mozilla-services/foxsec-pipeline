package bugzilla_alert_manager

import (
	"github.com/mozilla-services/foxsec-pipeline/contrib/common"
)

type AlertCollection struct {
	alerts   []*common.Alert
	category string
}

func CreateCollections(alerts []*common.Alert) []*AlertCollection {
	collections := map[string]*AlertCollection{}

	for _, alert := range alerts {
		if _, ok := collections[alert.Category]; ok {
			collections[alert.Category].alerts = append(collections[alert.Category].alerts, alert)
		}
		collections[alert.Category] = &AlertCollection{[]*common.Alert{alert}, alert.Category}
	}

	c := []*AlertCollection{}
	for _, collection := range collections {
		c = append(c, collection)
	}
	return c
}
