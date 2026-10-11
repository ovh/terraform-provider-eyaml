// Copyright (c) OVH SAS
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = &DecryptEphemeralResource{}

func NewDecryptEphemeralResource() ephemeral.EphemeralResource {
	return &DecryptEphemeralResource{}
}

type DecryptEphemeralResource struct {
}

type DecryptEphemeralResourceModel struct {
	PrivateKey    types.String `tfsdk:"private_key"`
	PublicKey     types.String `tfsdk:"public_key"`
	Data          types.String `tfsdk:"data"`
	DecryptedData types.String `tfsdk:"decrypted_data"`
}

func (e *DecryptEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decrypt"
}

func (e *DecryptEphemeralResource) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This ephemeral resource decrypts data using the given private and public key, without storing the result in the plan or state. This is similar to `eyaml decrypt` command line.",

		Attributes: map[string]schema.Attribute{
			"private_key": schema.StringAttribute{
				MarkdownDescription: "Private key used for decryption.",
				Sensitive:           true,
				Required:            true,
			},
			"public_key": schema.StringAttribute{
				MarkdownDescription: "Public key used for decryption.",
				Required:            true,
			},
			"data": schema.StringAttribute{
				MarkdownDescription: "Data to decrypt.",
				Required:            true,
			},
			"decrypted_data": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Decrypted data.",
			},
		},
	}
}

func (e *DecryptEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data DecryptEphemeralResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	encryptedDataStripped, err := stripEyamlEnvelope(data.Data.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Decryption error", fmt.Sprintf("Unable to strip eyaml envelope, got error: %s", err))
		return
	}

	decryptedData, err := decrypt(encryptedDataStripped, strings.TrimSpace(data.PrivateKey.ValueString()), strings.TrimSpace(data.PublicKey.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Decryption error", fmt.Sprintf("Unable to decrypt data, got error: %s", err))
		return
	}

	data.DecryptedData = types.StringValue(decryptedData)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
