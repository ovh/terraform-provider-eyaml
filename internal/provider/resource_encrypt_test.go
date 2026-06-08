package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEncryptedDataResource_data(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
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
					testAccEncryptedDataResourceCheckWriteOnlyNotPersisted(),
					resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data_wo_version"),
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, firstExpectedValue),
				),
			},
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, secondExpectedValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, secondExpectedValue),
				),
			},
		},
	})
}

func TestAccEncryptedDataResource_dataWO(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	firstExpectedValue := "this-write-only-value-will-be-encrypted"
	secondExpectedValue := "this-write-only-value-will-be-encrypted-too"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEncryptedDataResourceWriteOnlyConfig(publicKey, firstExpectedValue, "1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "public_key", publicKey),
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "data_wo_version", "1"),
					resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data"),
					testAccEncryptedDataResourceCheckWriteOnlyNotPersisted(),
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, firstExpectedValue),
				),
			},
			{
				Config:   testAccEncryptedDataResourceWriteOnlyConfig(publicKey, "ephemeral-run-value", "1"),
				PlanOnly: true,
			},
			{
				Config: testAccEncryptedDataResourceWriteOnlyConfig(publicKey, secondExpectedValue, "2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "data_wo_version", "2"),
					resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data"),
					testAccEncryptedDataResourceCheckWriteOnlyNotPersisted(),
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, secondExpectedValue),
				),
			},
		},
	})
}

func TestAccEncryptedDataResource_invalidConfig(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccEncryptedDataResourceWriteOnlyOnlyDataConfig(publicKey, "missing-version"),
				ExpectError: regexp.MustCompile("data_wo` and `data_wo_version` must be configured together"),
			},
			{
				Config:      testAccEncryptedDataResourceWriteOnlyOnlyVersionConfig(publicKey, "1"),
				ExpectError: regexp.MustCompile("data_wo` and `data_wo_version` must be configured together"),
			},
			{
				Config:      testAccEncryptedDataResourceMixedInputConfig(publicKey, "legacy", "write-only", "1"),
				ExpectError: regexp.MustCompile("Configure either `data` or the pair `data_wo` and `data_wo_version`, but not\\s+both"),
			},
			{
				Config:      testAccEncryptedDataResourceMissingInputConfig(publicKey),
				ExpectError: regexp.MustCompile("Configure either `data` or the pair `data_wo` and `data_wo_version`"),
			},
		},
	})
}

func testAccEncryptedDataResourceKeys(t *testing.T) (string, string) {
	t.Helper()

	publicKeyBytes, err := os.ReadFile("testdata/keys/public_key.pkcs7.pem")
	if err != nil {
		t.Fatal(err)
	}

	privateKeyBytes, err := os.ReadFile("testdata/keys/private_key.pkcs7.pem")
	if err != nil {
		t.Fatal(err)
	}

	return string(publicKeyBytes), string(privateKeyBytes)
}

func testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, expectedValue string) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith("eyaml_encrypt.test", "encrypted_data", func(v string) error {
		re := regexp.MustCompile(`ENC\[PKCS7,(.+)\]`)
		matches := re.FindStringSubmatch(v)
		if len(matches) != 2 {
			return fmt.Errorf("expected encrypted value to be in format ENC[PKCS7,..], got %s", v)
		}

		decryptedValue, err := decrypt(matches[1], privateKey, publicKey)
		if err != nil {
			return err
		}

		if decryptedValue != expectedValue {
			return fmt.Errorf("expected decrypted value to be %s, got %s", expectedValue, decryptedValue)
		}

		return nil
	})
}

func testAccEncryptedDataResourceCheckWriteOnlyNotPersisted() resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data_wo"),
	)
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

func testAccEncryptedDataResourceWriteOnlyConfig(publicKey, dataWO, dataWOVersion string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data_wo         = "%s"
	data_wo_version = "%s"
	public_key      = <<EOT
%sEOT
}
`, dataWO, dataWOVersion, publicKey)
}

func testAccEncryptedDataResourceWriteOnlyOnlyDataConfig(publicKey, dataWO string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data_wo    = "%s"
	public_key = <<EOT
%sEOT
}
`, dataWO, publicKey)
}

func testAccEncryptedDataResourceWriteOnlyOnlyVersionConfig(publicKey, dataWOVersion string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data_wo_version = "%s"
	public_key      = <<EOT
%sEOT
}
`, dataWOVersion, publicKey)
}

func testAccEncryptedDataResourceMixedInputConfig(publicKey, data, dataWO, dataWOVersion string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data            = "%s"
	data_wo         = "%s"
	data_wo_version = "%s"
	public_key      = <<EOT
%sEOT
}
`, data, dataWO, dataWOVersion, publicKey)
}

func testAccEncryptedDataResourceMissingInputConfig(publicKey string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	public_key = <<EOT
%sEOT
}
`, publicKey)
}
