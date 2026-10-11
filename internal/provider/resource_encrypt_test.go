package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
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
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "data_wo_reference", testAccDataHash(firstExpectedValue)),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectSensitiveValue("eyaml_encrypt.test", tfjsonpath.New("data")),
				},
			},
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, secondExpectedValue),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("eyaml_encrypt.test", plancheck.ResourceActionReplace),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, secondExpectedValue),
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "data_wo_reference", testAccDataHash(secondExpectedValue)),
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
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
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
					resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data_wo_reference"),
				),
			},
			{
				Config:   testAccEncryptedDataResourceWriteOnlyConfig(publicKey, "ephemeral-run-value", "1"),
				PlanOnly: true,
			},
			{
				Config: testAccEncryptedDataResourceWriteOnlyConfig(publicKey, secondExpectedValue, "2"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("eyaml_encrypt.test", plancheck.ResourceActionReplace),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "data_wo_version", "2"),
					resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data"),
					testAccEncryptedDataResourceCheckWriteOnlyNotPersisted(),
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, secondExpectedValue),
					resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data_wo_reference"),
				),
			},
		},
	})
}

func TestAccEncryptedDataResource_dataWOReferenceUpgrade(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)
	config := testAccEncryptedDataResourceWriteOnlyConfig(publicKey, "this-value-was-hashed-by-an-older-release", "1")

	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		Steps: []resource.TestStep{
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"eyaml": {Source: "ovh/eyaml", VersionConstraint: "0.1.8"},
				},
				Config: config,
				Check:  resource.TestCheckResourceAttrSet("eyaml_encrypt.test", "data_wo_reference"),
			},
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Config:                   config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: resource.TestCheckNoResourceAttr("eyaml_encrypt.test", "data_wo_reference"),
			},
		},
	})
}

func TestAccEncryptedDataResource_block(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	expectedValue := "this-value-will-be-encrypted-as-a-block"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEncryptedDataResourceBlockConfig(publicKey, expectedValue, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "block", "true"),
					resource.TestMatchResourceAttr("eyaml_encrypt.test", "encrypted_data", regexp.MustCompile(`\AENC\[PKCS7,[a-zA-Z0-9+/=]+\n`)),
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, expectedValue),
				),
			},
			{
				Config: testAccEncryptedDataResourceBlockConfig(publicKey, expectedValue, false),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("eyaml_encrypt.test", plancheck.ResourceActionReplace),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("eyaml_encrypt.test", "block", "false"),
					resource.TestMatchResourceAttr("eyaml_encrypt.test", "encrypted_data", regexp.MustCompile(`\AENC\[PKCS7,[a-zA-Z0-9+/=]+\]\z`)),
					testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, expectedValue),
				),
			},
		},
	})
}

func TestAccEncryptedDataResource_publicKeyRotation(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)
	newPublicKey, newPrivateKey := testGenerateKeyPair(t)
	expectedValue := "this-value-will-be-encrypted-with-a-new-key"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, expectedValue),
			},
			{
				Config: testAccEncryptedDataResourceConfig(newPublicKey, expectedValue),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("eyaml_encrypt.test", plancheck.ResourceActionReplace),
					},
				},
				Check: testAccEncryptedDataResourceCheckEncryptedValue(newPrivateKey, newPublicKey, expectedValue),
			},
		},
	})
}

func TestAccEncryptedDataResource_blockUnsetToFalseAndBack(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)
	expectedValue := "this-value-will-not-be-re-encrypted"
	sameEncryptedData := statecheck.CompareValue(compare.ValuesSame())

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, expectedValue),
				ConfigStateChecks: []statecheck.StateCheck{
					sameEncryptedData.AddStateValue("eyaml_encrypt.test", tfjsonpath.New("encrypted_data")),
				},
			},
			{
				Config: testAccEncryptedDataResourceBlockConfig(publicKey, expectedValue, false),
				ConfigStateChecks: []statecheck.StateCheck{
					sameEncryptedData.AddStateValue("eyaml_encrypt.test", tfjsonpath.New("encrypted_data")),
				},
			},
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, expectedValue),
				ConfigStateChecks: []statecheck.StateCheck{
					sameEncryptedData.AddStateValue("eyaml_encrypt.test", tfjsonpath.New("encrypted_data")),
				},
			},
		},
	})
}

func TestAccEncryptedDataResource_importUnsupported(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEncryptedDataResourceConfig(publicKey, "this-value-cannot-be-imported"),
			},
			{
				ResourceName:  "eyaml_encrypt.test",
				ImportState:   true,
				ImportStateId: "1",
				ExpectError:   regexp.MustCompile(`Resource Import Not Implemented`),
			},
		},
	})
}

func TestAccEncryptedDataResource_invalidConfig(t *testing.T) {
	publicKey, _ := testAccEncryptedDataResourceKeys(t)

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
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

func testAccDataHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func testAccEncryptedDataResourceCheckEncryptedValue(privateKey, publicKey, expectedValue string) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith("eyaml_encrypt.test", "encrypted_data", func(v string) error {
		re := regexp.MustCompile(`\AENC\[PKCS7,(.+)\]\z`)
		matches := re.FindStringSubmatch(strings.Join(strings.Fields(v), ""))
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

func testAccEncryptedDataResourceBlockConfig(publicKey, data string, block bool) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data       = "%s"
	block      = %t
	public_key = <<EOT
%sEOT
}
`, data, block, publicKey)
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
