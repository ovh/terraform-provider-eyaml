package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &EncryptedDataResource{}
var _ resource.ResourceWithImportState = &EncryptedDataResource{}

func NewEncryptedDataResource() resource.Resource {
	return &EncryptedDataResource{}
}

type EncryptedDataResource struct {
}

type EncryptedDataResourceModel struct {
	PublicKey     types.String `tfsdk:"public_key"`
	Data          types.String `tfsdk:"data"`
	EncryptedData types.String `tfsdk:"encrypted_data"`
	Id            types.String `tfsdk:"id"`
}

func (r *EncryptedDataResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_encrypt"
}

func (r *EncryptedDataResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "This resource encrypt a data using the given public key. This is similar to `eyaml encrypt` command line.",

		Attributes: map[string]schema.Attribute{
			"public_key": schema.StringAttribute{
				MarkdownDescription: "Public key used for the encryption.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"data": schema.StringAttribute{
				MarkdownDescription: "Data to encrypt.",
				Required:            true,
				Sensitive:           true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"encrypted_data": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Encrypted data.",
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "ID of the encrypted data.",
				Computed:            true,
			},
		},
	}
}

func (r *EncryptedDataResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
}

func (r *EncryptedDataResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data *EncryptedDataResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	encryptedData, err := encrypt(data.Data.ValueString(), strings.TrimSpace(data.PublicKey.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Encryption error", fmt.Sprintf("Unable to encrypt data, got error: %s", err))
		return
	}

	data.EncryptedData = types.StringValue(fmt.Sprintf("ENC[PKCS7,%s]", encryptedData))
	data.Id = types.StringValue(strconv.FormatInt(time.Now().Unix(), 10))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EncryptedDataResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *EncryptedDataResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EncryptedDataResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *EncryptedDataResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EncryptedDataResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *EncryptedDataResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *EncryptedDataResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
