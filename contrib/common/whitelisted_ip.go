package common

import (
	"fmt"
	"time"
)

const (
	IP_TYPE    = "ip"
	EMAIL_TYPE = "email"
)

type WhitelistedObject struct {
	Object    string    `json:"object"`
	Type      string    `json:"type"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy string    `json:"created_by"`
}

func NewWhitelistedObject(object, typestr string, expiresAt time.Time, createdBy string) (*WhitelistedObject, error) {
	if typestr != IP_TYPE && typestr != EMAIL_TYPE {
		return nil, fmt.Errorf("Invalid typestr %s. Only %s and %s allowed", typestr, IP_TYPE, EMAIL_TYPE)
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour * 24)
	}
	return &WhitelistedObject{
		Object:    object,
		Type:      typestr,
		ExpiresAt: expiresAt,
		CreatedBy: createdBy,
	}, nil
}

func (wo *WhitelistedObject) IsExpired() bool {
	return wo.ExpiresAt.Before(time.Now())
}
