package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &DecryptDataSource{}

func NewDecryptDataSource() datasource.DataSource {
	return &DecryptDataSource{}
}

type DecryptDataSource struct {
}

type DecryptDataSourceModel struct {
	PrivateKey    types.String `tfsdk:"private_key"`
	PublicKey     types.String `tfsdk:"public_key"`
	Data          types.String `tfsdk:"data"`
	DecryptedData types.String `tfsdk:"decrypted_data"`
	Id            types.String `tfsdk:"id"`
}

func (d *DecryptDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decrypt"
}

func (d *DecryptDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This data source decrypt a data using the given private and public key. This is similar to `eyaml decrypt` command line.",

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
			"id": schema.StringAttribute{
				MarkdownDescription: "ID of the encrypted data.",
				Computed:            true,
			},
		},
	}
}

func (d *DecryptDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
}

func (d *DecryptDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data DecryptDataSourceModel

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
	data.Id = types.StringValue(strconv.FormatInt(time.Now().Unix(), 10))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
