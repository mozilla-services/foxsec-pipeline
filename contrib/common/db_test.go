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
			{Key: META_STATUS, Value: ALERT_NEW},
			// Add an arbitrary custom key here too
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

	na.SetMetadata(META_STATUS, ALERT_ESCALATED)
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

func TestExemptedObjectDB(t *testing.T) {
	db, err := NewDBClient(context.Background(), "test")
	assert.NoError(t, err)

	eip, err := NewExemptedObject("127.0.0.1", "ip", time.Now().Add(time.Hour), "test")
	assert.NoError(t, err)

	err = db.SaveExemptedObject(context.Background(), eip)
	assert.NoError(t, err)

	eips, err := db.GetAllExemptedObjects(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(eips))
	assert.True(t, WOBJEqual(eip, eips[0]))

	expiredWip, err := NewExemptedObject("127.0.0.2", "ip", time.Now().Add(time.Duration(-1)*time.Hour), "test")
	assert.NoError(t, err)
	err = db.SaveExemptedObject(context.Background(), expiredWip)
	assert.NoError(t, err)
	eips, err = db.GetAllExemptedObjects(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(eips))

	err = db.RemoveExpiredExemptedObjects(context.Background())
	assert.NoError(t, err)

	eips, err = db.GetAllExemptedObjects(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(eips))
	assert.True(t, WOBJEqual(eip, eips[0]))

	err = db.DeleteExemptedObject(context.Background(), eip)
	assert.NoError(t, err)

	err = db.Close()
	assert.NoError(t, err)
}

func WOBJEqual(eipOne, eipTwo *ExemptedObject) bool {
	if eipOne.Type != eipTwo.Type {
		fmt.Printf("Type's did not match: %s != %s\n", eipOne.Type, eipTwo.Type)
		return false
	}
	if eipOne.Object != eipTwo.Object {
		fmt.Printf("Object's did not match: %s != %s\n", eipOne.Object, eipTwo.Object)
		return false
	}
	if eipOne.CreatedBy != eipTwo.CreatedBy {
		fmt.Printf("CreatedBy did not match: %s != %s\n", eipOne.CreatedBy, eipTwo.CreatedBy)
		return false
	}
	if !eipOne.ExpiresAt.Equal(eipTwo.ExpiresAt) {
		fmt.Printf("ExpiresAt did not match: %s != %s\n", eipOne.ExpiresAt, eipTwo.ExpiresAt)
		return false
	}
	return true
}
