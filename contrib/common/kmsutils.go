package common

import (
	"context"
	"encoding/base64"
	"os"
	"strings"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type KMSClient struct {
	client *cloudkms.KeyManagementClient
}

func NewKMSClient() (*KMSClient, error) {
	client, err := cloudkms.NewKeyManagementClient(context.Background())
	if err != nil {
		return nil, err
	}
	return &KMSClient{client: client}, nil
}

// Takes base64 ciphertext and decodes it.
func prepareSecret(ciphertext string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, "cloudkms://"))
}

func (kms *KMSClient) DecryptEnvVar(keyName, envVar string) (string, error) {
	v := os.Getenv(envVar)
	if !strings.HasPrefix(v, "cloudkms://") {
		return v, nil
	}
	ciphertext, err := prepareSecret(v)
	if err != nil {
		return "", err
	}
	return kms.DecryptSymmetric(keyName, ciphertext)
}

func (kms *KMSClient) DecryptSymmetric(keyName string, ciphertext []byte) (string, error) {
	ctx := context.Background()

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
	}
	// Call the API.
	resp, err := kms.client.Decrypt(ctx, req)
	if err != nil {
		return "", err
	}
	return string(resp.Plaintext), nil
}
