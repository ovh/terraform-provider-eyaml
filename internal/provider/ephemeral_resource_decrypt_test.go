// Copyright (c) OVH SAS
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

var testAccProtoV6ProviderFactoriesWithEcho = map[string]func() (tfprotov6.ProviderServer, error){
	"eyaml": testAccProtoV6ProviderFactories["eyaml"],
	"echo":  echoprovider.NewProviderServer(),
}

func TestAccDecryptEphemeralResource(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)
	expectedValue := "this-value-will-be-decrypted-ephemerally"

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccDecryptEphemeralResourceConfig(privateKey, publicKey, fmt.Sprintf("%q", expectedValue)),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data"), knownvalue.StringExact(expectedValue)),
				},
			},
		},
	})
}

func TestAccDecryptEphemeralResource_invalidEnvelope(t *testing.T) {
	publicKey, privateKey := testAccEncryptedDataResourceKeys(t)

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config:      testAccDecryptEphemeralResourceInvalidEnvelopeConfig(privateKey, publicKey),
				ExpectError: regexp.MustCompile(`encryption envelope`),
			},
		},
	})
}

func testAccDecryptEphemeralResourceConfig(privateKey, publicKey, data string) string {
	return fmt.Sprintf(`
resource "eyaml_encrypt" "test" {
	data       = %[3]s
	block      = true
	public_key = <<EOT
%[2]sEOT
}

ephemeral "eyaml_decrypt" "test" {
	private_key = <<EOT
%[1]sEOT
	public_key = <<EOT
%[2]sEOT
	data = eyaml_encrypt.test.encrypted_data
}

provider "echo" {
	data = ephemeral.eyaml_decrypt.test.decrypted_data
}

resource "echo" "test" {}
`, privateKey, publicKey, data)
}

func testAccDecryptEphemeralResourceInvalidEnvelopeConfig(privateKey, publicKey string) string {
	return fmt.Sprintf(`
ephemeral "eyaml_decrypt" "test" {
	private_key = <<EOT
%[1]sEOT
	public_key = <<EOT
%[2]sEOT
	data = "not-an-encrypted-value"
}

provider "echo" {
	data = ephemeral.eyaml_decrypt.test.decrypted_data
}

resource "echo" "test" {}
`, privateKey, publicKey)
}
