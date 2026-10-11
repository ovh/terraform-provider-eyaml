package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEncryption(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)
	secret := "this-value-will-be-encrypted"
	_, err := encrypt(secret, publicKey)
	if err != nil {
		t.Errorf("failed to encrypt secret, got: %s", err)
		t.FailNow()
	}
}

func TestDecryption(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
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

func testPKCS8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestDecryption_pkcs8(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	rsaKey, err := getPrivateKey(strings.TrimSpace(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	expectedSecret := "this-value-will-be-encrypted"
	encryptedSecret, err := encrypt(expectedSecret, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	decryptedSecret, err := decrypt(encryptedSecret, testPKCS8PEM(t, rsaKey), publicKey)
	if err != nil {
		t.Fatalf("failed to decrypt secret with a PKCS#8 key, got: %s", err)
	}
	if decryptedSecret != expectedSecret {
		t.Fatalf("decrypted secret does not match expected secret, got: %s, expected: %s", decryptedSecret, expectedSecret)
	}
}

func TestDecryption_invalidKeys(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	_, ed25519Key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		privateKey, publicKey, want string
	}{
		"invalid private key": {"not-a-pem", publicKey, "private_key: invalid PEM block"},
		"invalid public key":  {privateKey, "not-a-pem", "public_key: invalid PEM block"},
		"non-RSA private key": {testPKCS8PEM(t, ed25519Key), publicKey, "private_key: not an RSA key"},
		"empty certificate":   {privateKey, testEmptyCertificatePEM, "public_key: no certificate found"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decrypt("", strings.TrimSpace(tc.privateKey), strings.TrimSpace(tc.publicKey))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("expected error %q, got: %v", tc.want, err)
			}
		})
	}
}

const testEmptyCertificatePEM = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"

func TestEncryption_emptyCertificate(t *testing.T) {
	_, err := encrypt("this-value-will-not-be-encrypted", testEmptyCertificatePEM)
	if want := "public_key: no certificate found"; err == nil || err.Error() != want {
		t.Fatalf("expected error %q, got: %v", want, err)
	}
}

func testGenerateKeyPair(t *testing.T) (publicKey, privateKey string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	publicKey = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return publicKey, privateKey
}

var hclTemplateEscaper = strings.NewReplacer("${", "$${", "%{", "%%{")

// shortcut: strconv.Quote emits \a, \x.. for control characters, which HCL rejects; extend if a test needs them.
func testAccHCLString(s string) string {
	return hclTemplateEscaper.Replace(strconv.Quote(s))
}
