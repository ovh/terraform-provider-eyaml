## Unreleased

BREAKING CHANGES:

* resource/eyaml_encrypt: `data_wo_reference` is null when you use `data_wo`, and the attribute is deprecated. Use `data_wo_version` to track changes. On the next refresh, Terraform removes a hash that an older release stored. If you run with `-refresh=false`, run one normal refresh to remove it.
* resource/eyaml_encrypt: `terraform import` is no longer supported. Import never produced a usable state, because the resource has no remote object.

FEATURES:

* ephemeral/eyaml_decrypt: New ephemeral resource. It decrypts data without storing the result in the plan or state. It requires Terraform 1.10 or later.

ENHANCEMENTS:

* Decryption accepts RSA private keys in PKCS#8 (`PRIVATE KEY`) format.
* Key errors name the argument that failed, for example `private_key: invalid PEM block`.

BUG FIXES:

* resource/eyaml_encrypt: An in-place update, for example adding `block = false`, no longer fails with `Provider returned invalid result object after apply`.
* A `public_key` with an empty `CERTIFICATE` block no longer crashes the provider. The provider returns `public_key: no certificate found`.

## 0.1.0 

* Initial release.
