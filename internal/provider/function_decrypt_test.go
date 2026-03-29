package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccDecryptFunction(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("testdata/keys/public_key.pkcs7.pem")
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(publicKeyBytes)
	privateKeyBytes, err := os.ReadFile("testdata/keys/private_key.pkcs7.pem")
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(privateKeyBytes)
	resource.Test(t, resource.TestCase{
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

func TestAccDecryptFunction_InvalidEnvelope(t *testing.T) {
	publicKeyBytes, err := os.ReadFile("testdata/keys/public_key.pkcs7.pem")
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(publicKeyBytes)
	privateKeyBytes, err := os.ReadFile("testdata/keys/private_key.pkcs7.pem")
	if err != nil {
		t.Fatal(err)
	}
	privateKey := string(privateKeyBytes)
	resource.Test(t, resource.TestCase{
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

func testAccDecryptFunctionConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
output "decrypted" {
  value = provider::eyaml::decrypt(
    <<EOT
%s
EOT
    ,
    <<EOT
%sEOT
    ,
    "ENC[PKCS7,MIIBfQYJKoZIhvcNAQcDoIIBbjCCAWoCAQAxggEfMIIBGwIBADAFMAACAQEwCwYJKoZIhvcNAQEBBIIBAJRWoo875CLTzgo3vlBaiN8SnJgXoWDyvBKx7xNRvZoboYZltHs6lGtpaHB4ykCZD6so8YNRmJOoBeDnP2lyBSWZkCv0cU1lmToEG329bRBd/P0y1rtRW44JRbGcCR/WunXETq8RwAvuGikXwkirD9SmdSuytgCEA0nhRGLwDeJnwQojbhxqy6PI4j9I5MAjt96smn+RP3KQSmbPAFSfIFLp5eGUl5qxAqli0Nl02JP+MK04sVSa7sI3XBzYjn7AeUTlryWHdQ1xuNhMV8mwGxhJzQ+obo4ptHQ9jo9+xIoUPiK8cl0wDpxDqTAvTlQ7wxT+SCiCZUnLEoQtGXQTRBYwQgYJKoZIhvcNAQcBMBEGBSsOAwIHBAhsxVuocgO2gKAiBCBO1l7bS2BXrqDHSb4jwZNKDRXRTcdRf93BTAOnUAWN8w==]"
  )
}
`, privateKey, publicKey)
}

func testAccDecryptFunctionInvalidEnvelopeConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
output "decrypted" {
  value = provider::eyaml::decrypt(
    <<EOT
%s
EOT
    ,
    <<EOT
%sEOT
    ,
    "not-an-encrypted-value"
  )
}
`, privateKey, publicKey)
}
