// Copyright (c) OVH SAS
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestEncryptedDataResourceRead_dataWOReference(t *testing.T) {
	ctx := context.Background()
	r := NewEncryptedDataResource()
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	schema := schemaResp.Schema

	for name, tc := range map[string]struct {
		data      tftypes.Value
		wantValue types.String
	}{
		"hash left by an older release is cleared for data_wo": {
			data:      tftypes.NewValue(tftypes.String, nil),
			wantValue: types.StringNull(),
		},
		"hash is kept for data": {
			data:      tftypes.NewValue(tftypes.String, "plaintext"),
			wantValue: types.StringValue("stored-hash"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := tfsdk.State{
				Schema: schema,
				Raw: tftypes.NewValue(schema.Type().TerraformType(ctx), map[string]tftypes.Value{
					"public_key":        tftypes.NewValue(tftypes.String, "public-key"),
					"data":              tc.data,
					"data_wo":           tftypes.NewValue(tftypes.String, nil),
					"data_wo_version":   tftypes.NewValue(tftypes.String, "1"),
					"data_wo_reference": tftypes.NewValue(tftypes.String, "stored-hash"),
					"block":             tftypes.NewValue(tftypes.Bool, nil),
					"encrypted_data":    tftypes.NewValue(tftypes.String, "ENC[PKCS7,abc]"),
					"id":                tftypes.NewValue(tftypes.String, "1"),
				}),
			}
			resp := &resource.ReadResponse{State: state}
			r.Read(ctx, resource.ReadRequest{State: state}, resp)
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}

			var got types.String
			resp.Diagnostics.Append(resp.State.GetAttribute(ctx, path.Root("data_wo_reference"), &got)...)
			if resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
			if !got.Equal(tc.wantValue) {
				t.Fatalf("expected data_wo_reference %s, got %s", tc.wantValue, got)
			}
		})
	}
}
