# Terraform Provider Eyaml

Terraform provider for manipulating encrypted data using [eyaml](https://github.com/voxpupuli/hiera-eyaml). It initially aimed to encrypt data for puppet.

## Supported encryption methods

This provider only supports PKCS7 as encryption method.

## Encrypt Resource Input Modes

The `eyaml_encrypt` resource now supports two mutually exclusive ways to provide plaintext:

1. `data` for the legacy stateful workflow.
2. `data_wo` together with `data_wo_version` for a write-only workflow that avoids storing the plaintext in Terraform state.

When using `data_wo`, update `data_wo_version` whenever the plaintext changes so Terraform can detect the replacement.

The `data_wo` attribute uses Terraform write-only schema support, which requires Terraform 1.11 or later. The legacy `data` attribute remains available on older supported Terraform versions.

Example using the write-only workflow:

```terraform
resource "eyaml_encrypt" "secret" {
   data_wo         = "this-value-will-be-encrypted"
   data_wo_version = "1"
   public_key      = <<EOT
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
EOT
}
```

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.9
- [Go](https://golang.org/doc/install) >= 1.20

## Building The Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the Go `install` command:

```shell
go install
```

## Adding Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules).
Please see the Go documentation for the most up to date information about using Go modules.

To add a new dependency `github.com/author/dependency` to your Terraform provider:

```shell
go get github.com/author/dependency
go mod tidy
```

Then commit the changes to `go.mod` and `go.sum`.

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `go install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `make docs`.

In order to run the full suite of Acceptance tests, run `make testacc`.

```shell
make testacc
```

## Releasing

Builds and releases are automated with GitHub Actions and
[GoReleaser](https://github.com/goreleaser/goreleaser/).

Currently there are a few manual steps to this:

1. Kick off the release:

   ```sh
   RELEASE_VERSION=v... \
   make release
   ```

2. Publish release:

   The Action creates the release, but leaves it in "draft" state. Open it up in
   a [browser](https://github.com/grafana/terraform-provider-grafana/releases)
   and if all looks well, click the `Auto-generate release notes` button and mash the publish button.
