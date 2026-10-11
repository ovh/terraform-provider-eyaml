package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDecryptFunction(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDecryptFunctionConfig(privateKey, publicKey),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckOutput("decrypted", "this-value-will-be-encrypted"),
				),
			},
		},
	})
}

func TestAccDecryptFunction_block(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDecryptFunctionBlockConfig(privateKey, publicKey),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckOutput("decrypted", "this-value-will-be-encrypted"),
				),
			},
		},
	})
}

func TestAccDecryptFunction_InvalidEnvelope(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccDecryptFunctionInvalidEnvelopeConfig(privateKey, publicKey),
				ExpectError: regexp.MustCompile(`encryption envelope`),
			},
		},
	})
}

func TestAccDecryptFunction_emptyCertificate(t *testing.T) {
	_, privateKey := testAccEncryptedDataResourceKeys(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccDecryptFunctionConfig(privateKey, testEmptyCertificatePEM),
				ExpectError: regexp.MustCompile(`public_key: no certificate found`),
			},
		},
	})
}

func testAccDecryptFunctionConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
output "decrypted" {
  value = provider::eyaml::decrypt(
    %[1]s
    ,
    %[2]s
    ,
    "ENC[PKCS7,MIIBfQYJKoZIhvcNAQcDoIIBbjCCAWoCAQAxggEfMIIBGwIBADAFMAACAQEwCwYJKoZIhvcNAQEBBIIBAJRWoo875CLTzgo3vlBaiN8SnJgXoWDyvBKx7xNRvZoboYZltHs6lGtpaHB4ykCZD6so8YNRmJOoBeDnP2lyBSWZkCv0cU1lmToEG329bRBd/P0y1rtRW44JRbGcCR/WunXETq8RwAvuGikXwkirD9SmdSuytgCEA0nhRGLwDeJnwQojbhxqy6PI4j9I5MAjt96smn+RP3KQSmbPAFSfIFLp5eGUl5qxAqli0Nl02JP+MK04sVSa7sI3XBzYjn7AeUTlryWHdQ1xuNhMV8mwGxhJzQ+obo4ptHQ9jo9+xIoUPiK8cl0wDpxDqTAvTlQ7wxT+SCiCZUnLEoQtGXQTRBYwQgYJKoZIhvcNAQcBMBEGBSsOAwIHBAhsxVuocgO2gKAiBCBO1l7bS2BXrqDHSb4jwZNKDRXRTcdRf93BTAOnUAWN8w==]"
  )
}
`, testAccHCLString(privateKey), testAccHCLString(publicKey))
}

func testAccDecryptFunctionInvalidEnvelopeConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
output "decrypted" {
  value = provider::eyaml::decrypt(
    %[1]s
    ,
    %[2]s
    ,
    "not-an-encrypted-value"
  )
}
`, testAccHCLString(privateKey), testAccHCLString(publicKey))
}

func testAccDecryptFunctionBlockConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
  data       = "this-value-will-be-encrypted"
  block      = true
  public_key = %[1]s
}

output "decrypted" {
  value = provider::eyaml::decrypt(
    %[2]s
    ,
    %[3]s
    ,
    eyaml_encrypt.test.encrypted_data
  )
}
`, testAccHCLString(publicKey), testAccHCLString(privateKey), testAccHCLString(publicKey))
}
