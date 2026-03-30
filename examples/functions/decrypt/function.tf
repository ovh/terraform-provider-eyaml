output "decrypted" {
  value     = provider::eyaml::decrypt(var.private_key, var.public_key, var.encrypted_data)
  sensitive = true
}
