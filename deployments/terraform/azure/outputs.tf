output "workload_identity_client_id" {
  description = "Annotate the service account with azure.workload.identity/client-id = this value"
  value       = azurerm_user_assigned_identity.heal.client_id
}

output "key_vault_uri" {
  description = "Key Vault holding the database URL, audit key and webhook credential secrets"
  value       = azurerm_key_vault.heal.vault_uri
}

output "audit_container" {
  description = "Immutable blob container receiving audit chains"
  value       = "${azurerm_storage_account.audit.name}/${azurerm_storage_container.audit.name}"
}

output "stacks_share" {
  description = "Azure Files share backing the terraform-stacks PersistentVolume (azurefile CSI)"
  value       = "${azurerm_storage_account.stacks.name}/${azurerm_storage_share.stacks.name}"
}
