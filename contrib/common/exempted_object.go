package common

import (
	"fmt"
	"time"
)

const (
	IP_TYPE    = "ip"
	EMAIL_TYPE = "email"
)

type ExemptedObject struct {
	Object    string    `json:"object"`
	Type      string    `json:"type"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy string    `json:"created_by"`
}

func NewExemptedObject(object, typestr string, expiresAt time.Time, createdBy string) (*ExemptedObject, error) {
	if typestr != IP_TYPE && typestr != EMAIL_TYPE {
		return nil, fmt.Errorf("Invalid typestr %s. Only %s and %s allowed", typestr, IP_TYPE, EMAIL_TYPE)
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour * 24)
	}
	return &ExemptedObject{
		Object:    object,
		Type:      typestr,
		ExpiresAt: expiresAt,
		CreatedBy: createdBy,
	}, nil
}

func (eo *ExemptedObject) IsExpired() bool {
	return eo.ExpiresAt.Before(time.Now())
}
