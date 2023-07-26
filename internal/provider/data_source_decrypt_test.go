package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
