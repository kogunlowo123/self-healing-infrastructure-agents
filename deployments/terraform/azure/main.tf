terraform {
  required_version = ">= 1.7.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.5" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
  subscription_id = var.subscription_id
}

data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "heal" {
  name = var.resource_group_name
}

locals {
  name     = var.name
  location = data.azurerm_resource_group.heal.location
  # Storage and Key Vault names are global; derive a stable unique suffix.
  suffix = substr(sha1("${data.azurerm_client_config.current.subscription_id}${local.name}"), 0, 8)
}

# ------------------------------------------------------------------ database

resource "random_password" "db" {
  length  = 40
  special = false
}

resource "azurerm_postgresql_flexible_server" "heal" {
  name                          = "${local.name}-${local.suffix}"
  resource_group_name           = data.azurerm_resource_group.heal.name
  location                      = local.location
  version                       = "16"
  sku_name                      = var.db_sku
  storage_mb                    = var.db_storage_mb
  delegated_subnet_id           = var.db_subnet_id
  private_dns_zone_id           = var.db_private_dns_zone_id
  public_network_access_enabled = false
  administrator_login           = "heal"
  administrator_password        = random_password.db.result
  backup_retention_days         = 14
  geo_redundant_backup_enabled  = true
  zone                          = "1"
  high_availability {
    mode                      = "ZoneRedundant"
    standby_availability_zone = "2"
  }
  tags = var.tags
}

resource "azurerm_postgresql_flexible_server_configuration" "require_tls" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.heal.id
  value     = "on"
}

resource "azurerm_postgresql_flexible_server_database" "heal" {
  name      = "heal"
  server_id = azurerm_postgresql_flexible_server.heal.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# ----------------------------------------------------------------- key vault

resource "azurerm_key_vault" "heal" {
  name                          = "kv-heal-${local.suffix}"
  resource_group_name           = data.azurerm_resource_group.heal.name
  location                      = local.location
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "premium"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
  tags = var.tags
}

resource "azurerm_key_vault_secret" "database_url" {
  name         = "${local.name}-database-url"
  key_vault_id = azurerm_key_vault.heal.id
  value = format(
    "postgresql+asyncpg://heal:%s@%s:5432/heal?ssl=require",
    random_password.db.result, azurerm_postgresql_flexible_server.heal.fqdn,
  )
  content_type    = "sqlalchemy-url"
  expiration_date = var.secret_expiration_date
}

# ------------------------------------------------------------- audit (WORM)

resource "azurerm_storage_account" "audit" {
  name                            = "staudit${local.suffix}"
  resource_group_name             = data.azurerm_resource_group.heal.name
  location                        = local.location
  account_tier                    = "Standard"
  account_replication_type        = "GZRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false
  public_network_access_enabled   = false
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
  blob_properties {
    versioning_enabled = true
  }
  immutability_policy {
    allow_protected_append_writes = true
    state                         = "Unlocked"
    period_since_creation_in_days = var.audit_retention_days
  }
  tags = var.tags
}

resource "azurerm_storage_container" "audit" {
  name                  = "audit-chains"
  storage_account_id    = azurerm_storage_account.audit.id
  container_access_type = "private"
}

# ------------------------------------- Terraform stacks (Azure Files, SMB, RWX)

resource "azurerm_storage_account" "stacks" {
  name                            = "ststacks${local.suffix}"
  resource_group_name             = data.azurerm_resource_group.heal.name
  location                        = local.location
  account_tier                    = "Standard"
  account_replication_type        = "ZRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
  share_properties {
    retention_policy {
      days = 30
    }
  }
  tags = var.tags
}

resource "azurerm_storage_share" "stacks" {
  name               = "terraform-stacks"
  storage_account_id = azurerm_storage_account.stacks.id
  quota              = var.stacks_quota_gb
}

# ---------------------------------------------- workload identity (AKS)

resource "azurerm_user_assigned_identity" "heal" {
  name                = local.name
  resource_group_name = data.azurerm_resource_group.heal.name
  location            = local.location
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "heal" {
  name                = "${local.name}-aks"
  resource_group_name = data.azurerm_resource_group.heal.name
  parent_id           = azurerm_user_assigned_identity.heal.id
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:${var.namespace}:${var.service_account}"
  audience            = ["api://AzureADTokenExchange"]
}

resource "azurerm_role_assignment" "audit_writer" {
  scope                = azurerm_storage_container.audit.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.heal.principal_id
}

# Terraform remediation scope: one role assignment per scope the platform team
# delegates (e.g. the resource groups of stacks in scope).
resource "azurerm_role_assignment" "remediation" {
  for_each             = var.remediation_scopes
  scope                = each.value
  role_definition_name = var.remediation_role
  principal_id         = azurerm_user_assigned_identity.heal.principal_id
}
