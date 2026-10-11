ephemeral "eyaml_decrypt" "db_password" {
  private_key = file("${path.module}/keys/private_key.pkcs7.pem")
  public_key  = file("${path.module}/keys/public_key.pkcs7.pem")
  data        = yamldecode(file("${path.module}/common.eyaml"))["db_password"]
}
