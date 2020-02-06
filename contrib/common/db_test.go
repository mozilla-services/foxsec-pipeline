package common

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDB(t *testing.T) {
	db, err := NewDBClient(context.Background(), "test")
	assert.NoError(t, err)
	err = db.Close()
	assert.NoError(t, err)
}

func TestAlertDB(t *testing.T) {
	db, err := NewDBClient(context.Background(), "test")
	assert.NoError(t, err)

	id := "1234567890"
	a := &Alert{
		Id:        id,
		Timestamp: time.Now().Add(time.Duration(-5) * time.Minute),
		Metadata: []*AlertMeta{
			{Key: "status", Value: ALERT_NEW},
			{Key: "foo", Value: "bar"},
		},
	}
	err = db.SaveAlert(context.Background(), a)
	assert.NoError(t, err)

	na, err := db.GetAlert(context.Background(), id)
	assert.NoError(t, err)
	assert.Equal(t, a.Id, na.Id)
	assert.Equal(t, a.Metadata, na.Metadata)
	assert.True(t, a.Timestamp.Equal(na.Timestamp))

	na.SetMetadata("status", ALERT_ESCALATED)
	err = db.SaveAlert(context.Background(), na)
	assert.NoError(t, err)
	nna, err := db.GetAlert(context.Background(), id)
	assert.NoError(t, err)
	assert.True(t, nna.IsStatus(ALERT_ESCALATED))
	assert.True(t, a.Timestamp.Equal(nna.Timestamp))

	alerts, err := db.GetAllAlerts(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(alerts))
	assert.Equal(t, a.Id, alerts[0].Id)
	assert.True(t, a.Timestamp.Equal(alerts[0].Timestamp))
	assert.Equal(t, nna.Metadata, alerts[0].Metadata)

	err = db.RemoveAlertsOlderThan(context.Background(), time.Nanosecond)
	assert.NoError(t, err)

	alerts, err = db.GetAllAlerts(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 0, len(alerts))

	err = db.Close()
	assert.NoError(t, err)
}

func TestWhitelistedObjectDB(t *testing.T) {
	db, err := NewDBClient(context.Background(), "test")
	assert.NoError(t, err)

	wip, err := NewWhitelistedObject("127.0.0.1", "ip", time.Now().Add(time.Hour), "test")
	assert.NoError(t, err)

	err = db.SaveWhitelistedObject(context.Background(), wip)
	assert.NoError(t, err)

	wips, err := db.GetAllWhitelistedObjects(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(wips))
	assert.True(t, WOBJEqual(wip, wips[0]))

	expiredWip, err := NewWhitelistedObject("127.0.0.2", "ip", time.Now().Add(time.Duration(-1)*time.Hour), "test")
	assert.NoError(t, err)
	err = db.SaveWhitelistedObject(context.Background(), expiredWip)
	assert.NoError(t, err)
	wips, err = db.GetAllWhitelistedObjects(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(wips))

	err = db.RemoveExpiredWhitelistedObjects(context.Background())
	assert.NoError(t, err)

	wips, err = db.GetAllWhitelistedObjects(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(wips))
	assert.True(t, WOBJEqual(wip, wips[0]))

	err = db.DeleteWhitelistedObject(context.Background(), wip)
	assert.NoError(t, err)

	err = db.Close()
	assert.NoError(t, err)
}

func WOBJEqual(wipOne, wipTwo *WhitelistedObject) bool {
	if wipOne.Type != wipTwo.Type {
		fmt.Printf("Type's did not match: %s != %s\n", wipOne.Type, wipTwo.Type)
		return false
	}
	if wipOne.Object != wipTwo.Object {
		fmt.Printf("Object's did not match: %s != %s\n", wipOne.Object, wipTwo.Object)
		return false
	}
	if wipOne.CreatedBy != wipTwo.CreatedBy {
		fmt.Printf("CreatedBy did not match: %s != %s\n", wipOne.CreatedBy, wipTwo.CreatedBy)
		return false
	}
	if !wipOne.ExpiresAt.Equal(wipTwo.ExpiresAt) {
		fmt.Printf("ExpiresAt did not match: %s != %s\n", wipOne.ExpiresAt, wipTwo.ExpiresAt)
		return false
	}
	return true
}
