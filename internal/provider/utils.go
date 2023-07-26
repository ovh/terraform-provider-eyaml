package provider

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.mozilla.org/pkcs7"
)

func getKeyCertificates(key string) ([]*x509.Certificate, error) {
	certificates := []*x509.Certificate{}
	block, rest := pem.Decode([]byte(key))
	if block == nil {
		return certificates, errors.New("invalid PEM block")
	}

	if len(rest) != 0 {
		return certificates, errors.New("invalid PEM block")
	}

	certificates, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return certificates, err
	}
	return certificates, nil
}

func getPrivateKey(key string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}

	if len(rest) != 0 {
		return nil, errors.New("invalid PEM block")
	}

	var (
		privateKey *rsa.PrivateKey
		err        error
	)
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("unknown key type")
	}
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func encrypt(value, key string) (string, error) {
	certificates, err := getKeyCertificates(key)
	if err != nil {
		return "", err
	}

	encryptedData, err := pkcs7.Encrypt([]byte(value), certificates)
	if err != nil {
		return "", err
	}

	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	_, err = encoder.Write(encryptedData)
	if err != nil {
		return "", err
	}
	err = encoder.Close()
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func decrypt(value, privateKeyRaw, publicKey string) (string, error) {
	privateKey, err := getPrivateKey(privateKeyRaw)
	if err != nil {
		return "", err
	}

	certificates, err := getKeyCertificates(publicKey)
	if err != nil {
		return "", err
	}

	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(value))
	decodedData, err := io.ReadAll(decoder)
	if err != nil {
		return "", err
	}

	encryptedData, err := pkcs7.Parse([]byte(decodedData))
	if err != nil {
		return "", err
	}

	decryptedData, err := encryptedData.Decrypt(certificates[0], privateKey)
	if err != nil {
		return "", err
	}

	return string(decryptedData), nil
}

func stripEyamlEnvelope(data string) (string, error) {
	if !strings.HasPrefix(data, "ENC[PKCS7,") {
		return "", fmt.Errorf("data does not appear to start with an encryption envelope")
	}

	if !strings.HasSuffix(data, "]") {
		return "", fmt.Errorf("data does not appear to end with an encryption envelope")
	}

	data = strings.TrimPrefix(data, "ENC[PKCS7,")
	data = strings.TrimSuffix(data, "]")

	return data, nil
}
