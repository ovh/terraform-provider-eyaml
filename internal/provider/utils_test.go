package provider

import (
	"os"
	"testing"
)

func TestEncryption(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("testdata/keys/public_key.pkcs7.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey := string(publicKeyBytes)
	secret := "this-value-will-be-encrypted"
	_, err = encrypt(secret, publicKey)
	if err != nil {
		t.Errorf("failed to encrypt secret, got: %s", err)
		t.FailNow()
	}
}

func TestDecryption(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("testdata/keys/public_key.pkcs7.pem")
	if err != nil {
		t.Error(err)
	}
	publicKey := string(publicKeyBytes)
	privateKeyBytes, err := os.ReadFile("testdata/keys/private_key.pkcs7.pem")
	if err != nil {
		t.Error(err)
	}
	privateKey := string(privateKeyBytes)
	expectedSecret := "this-value-will-be-encrypted"
	encryptedSecret := "MIIBfQYJKoZIhvcNAQcDoIIBbjCCAWoCAQAxggEfMIIBGwIBADAFMAACAQEwCwYJKoZIhvcNAQEBBIIBAJRWoo875CLTzgo3vlBaiN8SnJgXoWDyvBKx7xNRvZoboYZltHs6lGtpaHB4ykCZD6so8YNRmJOoBeDnP2lyBSWZkCv0cU1lmToEG329bRBd/P0y1rtRW44JRbGcCR/WunXETq8RwAvuGikXwkirD9SmdSuytgCEA0nhRGLwDeJnwQojbhxqy6PI4j9I5MAjt96smn+RP3KQSmbPAFSfIFLp5eGUl5qxAqli0Nl02JP+MK04sVSa7sI3XBzYjn7AeUTlryWHdQ1xuNhMV8mwGxhJzQ+obo4ptHQ9jo9+xIoUPiK8cl0wDpxDqTAvTlQ7wxT+SCiCZUnLEoQtGXQTRBYwQgYJKoZIhvcNAQcBMBEGBSsOAwIHBAhsxVuocgO2gKAiBCBO1l7bS2BXrqDHSb4jwZNKDRXRTcdRf93BTAOnUAWN8w=="
	decryptedSecret, err := decrypt(encryptedSecret, privateKey, publicKey)
	if err != nil {
		t.Errorf("failed to decrypt secret, got: %s", err)
		t.FailNow()
	}
	if decryptedSecret != expectedSecret {
		t.Errorf("decrypted secret does not match expected secret, got: %s, expected: %s", decryptedSecret, expectedSecret)
		t.FailNow()
	}
}
