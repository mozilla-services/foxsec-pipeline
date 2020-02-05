package common

import (
	"context"
	"encoding/json"
	"time"

	"cloud.google.com/go/datastore"
)

const (
	ALERT_NAMESPACE = "alerts"
	ALERT_KIND      = ALERT_NAMESPACE

	WHITELISTED_OBJ_NAMESPACE = "whitelisted_object"
)

type DBClient struct {
	dsClient *datastore.Client
}

func NewDBClient(ctx context.Context, projectID string) (*DBClient, error) {
	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return &DBClient{dsClient}, nil
}

func (db *DBClient) Close() error {
	return db.dsClient.Close()
}

type StateField struct {
	State string `datastore:"state,noindex" json:"state"`
}

func WhitelistedObjectToState(wobj *WhitelistedObject) (*StateField, error) {
	buf, err := json.Marshal(wobj)
	if err != nil {
		return nil, err
	}
	return &StateField{string(buf)}, nil
}

func StateToWhitelistedObject(sf *StateField) (*WhitelistedObject, error) {
	var wobj WhitelistedObject
	err := json.Unmarshal([]byte(sf.State), &wobj)
	if err != nil {
		return nil, err
	}
	return &wobj, nil
}

func (db *DBClient) whitelistedObjectKey(whitelistedObj *WhitelistedObject) *datastore.Key {
	nk := datastore.NameKey(whitelistedObj.Type, whitelistedObj.Object, nil)
	nk.Namespace = WHITELISTED_OBJ_NAMESPACE
	return nk
}

func (db *DBClient) RemoveExpiredWhitelistedObjects(ctx context.Context) error {
	ips, err := db.GetAllWhitelistedObjects(ctx)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsExpired() {
			err = db.DeleteWhitelistedObject(ctx, ip)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *DBClient) GetAllWhitelistedObjects(ctx context.Context) ([]*WhitelistedObject, error) {
	var wos []*WhitelistedObject
	for _, kind := range []string{IP_TYPE, EMAIL_TYPE} {
		nq := datastore.NewQuery(kind).Namespace(WHITELISTED_OBJ_NAMESPACE)
		states := []*StateField{}
		_, err := db.dsClient.GetAll(ctx, nq, &states)
		if err != nil {
			return nil, err
		}
		for _, state := range states {
			wo, err := StateToWhitelistedObject(state)
			if err != nil {
				return nil, err
			}
			wos = append(wos, wo)
		}
	}
	return wos, nil
}

func (db *DBClient) SaveWhitelistedObject(ctx context.Context, whitelistedObject *WhitelistedObject) error {
	tx, err := db.dsClient.NewTransaction(ctx)
	if err != nil {
		return err
	}

	sf, err := WhitelistedObjectToState(whitelistedObject)
	if err != nil {
		return err
	}

	if _, err = tx.Put(db.whitelistedObjectKey(whitelistedObject), sf); err != nil {
		return err
	}
	if _, err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (db *DBClient) DeleteWhitelistedObject(ctx context.Context, whitelistedObject *WhitelistedObject) error {
	return db.dsClient.Delete(ctx, db.whitelistedObjectKey(whitelistedObject))
}

func (db *DBClient) alertKey(ip string) *datastore.Key {
	nk := datastore.NameKey(ALERT_KIND, ip, nil)
	nk.Namespace = ALERT_NAMESPACE
	return nk
}

func StateToAlert(sf *StateField) (*Alert, error) {
	var alert Alert
	err := json.Unmarshal([]byte(sf.State), &alert)
	if err != nil {
		return nil, err
	}
	return &alert, nil
}

func AlertToState(a *Alert) (*StateField, error) {
	buf, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return &StateField{string(buf)}, nil
}

func (db *DBClient) GetAlert(ctx context.Context, alertId string) (*Alert, error) {
	var sf StateField
	err := db.dsClient.Get(ctx, db.alertKey(alertId), &sf)
	if err != nil {
		return nil, err
	}
	alert, err := StateToAlert(&sf)
	if err != nil {
		return nil, err
	}
	return alert, nil
}

func (db *DBClient) GetAllAlerts(ctx context.Context) ([]*Alert, error) {
	var alerts []*Alert
	var states []*StateField
	nq := datastore.NewQuery(ALERT_KIND).Namespace(ALERT_NAMESPACE)
	_, err := db.dsClient.GetAll(ctx, nq, &states)
	if err != nil {
		return alerts, err
	}
	for _, state := range states {
		alert, err := StateToAlert(state)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}

func (db *DBClient) SaveAlert(ctx context.Context, alert *Alert) error {
	tx, err := db.dsClient.NewTransaction(ctx)
	if err != nil {
		return err
	}

	sf, err := AlertToState(alert)
	if err != nil {
		return err
	}
	if _, err := tx.Put(db.alertKey(alert.Id), sf); err != nil {
		return err
	}
	if _, err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (db *DBClient) RemoveAlertsOlderThan(ctx context.Context, timeAgo time.Duration) error {
	alerts, err := db.GetAllAlerts(ctx)
	if err != nil {
		return err
	}

	for _, alert := range alerts {
		if !alert.IsStatus(ALERT_NEW) && alert.OlderThan(timeAgo) {
			err = db.DeleteAlert(ctx, alert)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (db *DBClient) DeleteAlert(ctx context.Context, alert *Alert) error {
	return db.dsClient.Delete(ctx, db.alertKey(alert.Id))
}
