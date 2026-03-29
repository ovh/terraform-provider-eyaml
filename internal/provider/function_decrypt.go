package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

var _ function.Function = &DecryptFunction{}

type DecryptFunction struct{}

func NewDecryptFunction() function.Function {
	return &DecryptFunction{}
}

func (f *DecryptFunction) Metadata(ctx context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "decrypt"
}

func (f *DecryptFunction) Definition(ctx context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Decrypts eyaml (PKCS7) encrypted data.",
		Description: "Decrypts data encrypted with eyaml using PKCS7. The data must be wrapped in the ENC[PKCS7,...] envelope. This is equivalent to the eyaml decrypt command.",
		MarkdownDescription: "Decrypts data encrypted with eyaml using PKCS7. " +
			"The data must be wrapped in the `ENC[PKCS7,...]` envelope. " +
			"This is equivalent to the `eyaml decrypt` command.\n\n" +
			"~> The `private_key` parameter value will be stored in plaintext " +
			"in the Terraform state. Use Terraform's built-in `sensitive` function " +
			"or `sensitive` output attribute to prevent the value from being displayed.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "private_key",
				Description:         "PEM-encoded RSA private key used for decryption.",
				MarkdownDescription: "PEM-encoded RSA private key used for decryption.",
			},
			function.StringParameter{
				Name:                "public_key",
				Description:         "PEM-encoded certificate (public key) used for decryption.",
				MarkdownDescription: "PEM-encoded certificate (public key) used for decryption.",
			},
			function.StringParameter{
				Name:                "data",
				Description:         "Encrypted data in ENC[PKCS7,...] format.",
				MarkdownDescription: "Encrypted data in `ENC[PKCS7,...]` format.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *DecryptFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var privateKey, publicKey, data string

	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &privateKey, &publicKey, &data))
	if resp.Error != nil {
		return
	}

	strippedData, err := stripEyamlEnvelope(data)
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error,
			function.NewArgumentFuncError(2, fmt.Sprintf("Error stripping eyaml envelope: %s", err)))
		return
	}

	decryptedData, err := decrypt(strippedData, strings.TrimSpace(privateKey), strings.TrimSpace(publicKey))
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error,
			function.NewFuncError(fmt.Sprintf("Error decrypting data: %s", err)))
		return
	}

	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, decryptedData))
}
