package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccExampleDataSource(t *testing.T) {
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
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccExampleDataSourceConfig(privateKey, publicKey),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.eyaml_decrypt.test", "decrypted_data", "this-value-will-be-encrypted"),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectSensitiveValue("data.eyaml_decrypt.test", tfjsonpath.New("private_key")),
					statecheck.ExpectSensitiveValue("data.eyaml_decrypt.test", tfjsonpath.New("decrypted_data")),
				},
			},
		},
	})
}

func TestAccExampleDataSource_block(t *testing.T) {
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
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccExampleDataSourceBlockConfig(privateKey, publicKey),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.eyaml_decrypt.test", "decrypted_data", "this-value-will-be-encrypted"),
				),
			},
		},
	})
}

func testAccExampleDataSourceConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
data "eyaml_decrypt" "test" {
	private_key = <<EOT
%s
EOT
	public_key = <<EOT
%sEOT
	data = "ENC[PKCS7,MIIBfQYJKoZIhvcNAQcDoIIBbjCCAWoCAQAxggEfMIIBGwIBADAFMAACAQEwCwYJKoZIhvcNAQEBBIIBAJRWoo875CLTzgo3vlBaiN8SnJgXoWDyvBKx7xNRvZoboYZltHs6lGtpaHB4ykCZD6so8YNRmJOoBeDnP2lyBSWZkCv0cU1lmToEG329bRBd/P0y1rtRW44JRbGcCR/WunXETq8RwAvuGikXwkirD9SmdSuytgCEA0nhRGLwDeJnwQojbhxqy6PI4j9I5MAjt96smn+RP3KQSmbPAFSfIFLp5eGUl5qxAqli0Nl02JP+MK04sVSa7sI3XBzYjn7AeUTlryWHdQ1xuNhMV8mwGxhJzQ+obo4ptHQ9jo9+xIoUPiK8cl0wDpxDqTAvTlQ7wxT+SCiCZUnLEoQtGXQTRBYwQgYJKoZIhvcNAQcBMBEGBSsOAwIHBAhsxVuocgO2gKAiBCBO1l7bS2BXrqDHSb4jwZNKDRXRTcdRf93BTAOnUAWN8w==]"
}
`, privateKey, publicKey)
}

func testAccExampleDataSourceBlockConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data       = "this-value-will-be-encrypted"
	block      = true
	public_key = <<EOT
%sEOT
}

data "eyaml_decrypt" "test" {
	private_key = <<EOT
%s
EOT
	public_key = <<EOT
%sEOT
	data = eyaml_encrypt.test.encrypted_data
}
`, publicKey, privateKey, publicKey)
}

func TestAccDecryptDataSource_invalidEnvelope(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccDecryptDataSourceDataConfig(privateKey, publicKey, "not-an-encrypted-value"),
				ExpectError: regexp.MustCompile(`encryption envelope`),
			},
		},
	})
}

func TestAccDecryptDataSource_wrongKeyPair(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)
	otherPublicKey, otherPrivateKey := testGenerateKeyPair(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccDecryptDataSourceWrongKeyPairConfig(publicKey, otherPrivateKey, otherPublicKey),
				ExpectError: regexp.MustCompile(`Unable to decrypt data`),
			},
		},
	})
}

func testAccDecryptDataSourceDataConfig(privateKey, publicKey, data string) string {
	return fmt.Sprintf(`
data "eyaml_decrypt" "test" {
	private_key = %[1]q
	public_key  = %[2]q
	data        = %[3]q
}
`, privateKey, publicKey, data)
}

func testAccDecryptDataSourceWrongKeyPairConfig(encryptPublicKey, decryptPrivateKey, decryptPublicKey string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data       = "this-value-cannot-be-decrypted-with-another-key"
	public_key = %[1]q
}

data "eyaml_decrypt" "test" {
	private_key = %[2]q
	public_key  = %[3]q
	data        = eyaml_encrypt.test.encrypted_data
}
`, encryptPublicKey, decryptPrivateKey, decryptPublicKey)
}
