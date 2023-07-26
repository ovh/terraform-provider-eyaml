// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure EncryptEyamlProvider satisfies various provider interfaces.
var _ provider.Provider = &EncryptEyamlProvider{}

// EncryptEyamlProvider defines the provider implementation.
type EncryptEyamlProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// EncryptEyamlProviderModel describes the provider data model.
type EncryptEyamlProviderModel struct {
}

func (p *EncryptEyamlProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "eyaml"
	resp.Version = p.version
}

func (p *EncryptEyamlProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *EncryptEyamlProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data EncryptEyamlProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (p *EncryptEyamlProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewEncryptedDataResource,
	}
}

func (p *EncryptEyamlProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewDecryptDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &EncryptEyamlProvider{
			version: version,
		}
	}
}
