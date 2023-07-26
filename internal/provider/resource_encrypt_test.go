package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEncryptedDataResource(t *testing.T) {
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
	firstExpectedValue := "this-value-will-be-encrypted"
	secondExpectedValue := "this-value-will-be-encrypted-too"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, firstExpectedValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "public_key", publicKey),
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "data", firstExpectedValue),
					resource.TestCheckResourceAttrWith("eyaml_encrypt.test", "encrypted_data", func(v string) error {
						re := regexp.MustCompile(`ENC\[PKCS7,(.+)\]`)
						matches := re.FindStringSubmatch(v)
						if len(matches) != 2 {
							return fmt.Errorf("expected encrypted value to be in format ENC[PKCS7,..], got %s", v)
						}
						decryptedValue, err := decrypt(matches[1], privateKey, publicKey)
						if err != nil {
							return err
						}
						if decryptedValue != firstExpectedValue {
							return fmt.Errorf("expected decrypted value to be %s, got %s", firstExpectedValue, decryptedValue)
						}
						return nil
					}),
				),
			},
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, secondExpectedValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrWith("eyaml_encrypt.test", "encrypted_data", func(v string) error {
						re := regexp.MustCompile(`ENC\[PKCS7,(.+)\]`)
						matches := re.FindStringSubmatch(v)
						if len(matches) != 2 {
							return fmt.Errorf("expected encrypted value to be in format ENC[PKCS7,..], got %s", v)
						}
						decryptedValue, err := decrypt(matches[1], privateKey, publicKey)
						if err != nil {
							return err
						}
						if decryptedValue != secondExpectedValue {
							t.Error(err)
							return fmt.Errorf("expected decrypted value to be %s, got %s", secondExpectedValue, decryptedValue)
						}
						return nil
					}),
				),
			},
		},
	})
}

func testAccEncryptedDataResourceConfig(publicKey, data string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data      = "%s"
	public_key = <<EOT
%sEOT
}
`, data, publicKey)
}
