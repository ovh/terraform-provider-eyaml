package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &EncryptedDataResource{}
var _ resource.ResourceWithValidateConfig = &EncryptedDataResource{}

func NewEncryptedDataResource() resource.Resource {
	return &EncryptedDataResource{}
}

type EncryptedDataResource struct {
}

type EncryptedDataResourceModel struct {
	PublicKey       types.String `tfsdk:"public_key"`
	Data            types.String `tfsdk:"data"`
	DataWO          types.String `tfsdk:"data_wo"`
	DataWOVersion   types.String `tfsdk:"data_wo_version"`
	DataWOReference types.String `tfsdk:"data_wo_reference"`
	Block           types.Bool   `tfsdk:"block"`
	EncryptedData   types.String `tfsdk:"encrypted_data"`
	Id              types.String `tfsdk:"id"`
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
				MarkdownDescription: "Data to encrypt. Configure either `data` or the pair `data_wo` and `data_wo_version`.",
				Optional:            true,
				Sensitive:           true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"data_wo": schema.StringAttribute{
				MarkdownDescription: "Write-only data to encrypt. Must be configured together with `data_wo_version` and cannot be combined with `data`.",
				Optional:            true,
				Sensitive:           true,
				WriteOnly:           true,
			},
			"data_wo_version": schema.StringAttribute{
				MarkdownDescription: "Version token for `data_wo`. Change this when `data_wo` changes so Terraform can detect the replacement.",
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"data_wo_reference": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "SHA256 hash of the value passed in `data`. Null when `data_wo` is used, because an unsalted hash in state lets anyone with state access guess low-entropy secrets.",
				DeprecationMessage:  "Use `data_wo_version` to track changes to `data_wo`. This attribute will be removed in a future major version.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"block": schema.BoolAttribute{
				MarkdownDescription: "Wrap `encrypted_data` on several lines instead of a single one, as `eyaml encrypt -o block` does.",
				Optional:            true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplaceIf(
						func(ctx context.Context, req planmodifier.BoolRequest, resp *boolplanmodifier.RequiresReplaceIfFuncResponse) {
							resp.RequiresReplace = req.StateValue.ValueBool() != req.ConfigValue.ValueBool()
						},
						"Requires replace when the block formatting changes.",
						"Requires replace when the block formatting changes.",
					),
				},
			},
			"encrypted_data": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Encrypted data.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "ID of the encrypted data.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *EncryptedDataResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data EncryptedDataResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.Data.IsUnknown() || data.DataWO.IsUnknown() || data.DataWOVersion.IsUnknown() {
		return
	}

	hasData := !data.Data.IsNull()
	hasDataWO := !data.DataWO.IsNull()
	hasDataWOVersion := !data.DataWOVersion.IsNull()

	switch {
	case hasData && !hasDataWO && !hasDataWOVersion:
		return
	case !hasData && hasDataWO && hasDataWOVersion:
		return
	case hasData && (hasDataWO || hasDataWOVersion):
		resp.Diagnostics.AddError("Invalid encryption input configuration", "Configure either `data` or the pair `data_wo` and `data_wo_version`, but not both.")
	case hasDataWO != hasDataWOVersion:
		resp.Diagnostics.AddError("Invalid encryption input configuration", "`data_wo` and `data_wo_version` must be configured together.")
	default:
		resp.Diagnostics.AddError("Missing encryption input configuration", "Configure either `data` or the pair `data_wo` and `data_wo_version`.")
	}
}

func dataHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func (r *EncryptedDataResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
}

func (r *EncryptedDataResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var configData *EncryptedDataResourceModel
	var planData *EncryptedDataResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &configData)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &planData)...)

	if resp.Diagnostics.HasError() {
		return
	}

	plaintext := configData.Data.ValueString()
	if configData.Data.IsNull() {
		plaintext = configData.DataWO.ValueString()
		planData.Data = types.StringNull()
		planData.DataWOReference = types.StringNull()
	} else {
		planData.DataWOReference = types.StringValue(dataHash(plaintext))
	}
	planData.DataWO = types.StringNull()

	encryptedData, err := encrypt(plaintext, strings.TrimSpace(planData.PublicKey.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Encryption error", fmt.Sprintf("Unable to encrypt data, got error: %s", err))
		return
	}

	planData.EncryptedData = types.StringValue(formatEncryptedData(encryptedData, planData.Block.ValueBool()))
	planData.Id = types.StringValue(strconv.FormatInt(time.Now().Unix(), 10))
	resp.Diagnostics.Append(resp.State.Set(ctx, &planData)...)
}

func (r *EncryptedDataResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data *EncryptedDataResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
	// Older releases stored an unsalted hash of data_wo, clear it without forcing replacement.
	if data.Data.IsNull() {
		data.DataWOReference = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EncryptedDataResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data *EncryptedDataResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
	data.DataWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *EncryptedDataResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data *EncryptedDataResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
}
