variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "self-healing-agents"
}

variable "subscription_id" {
  description = "Azure subscription"
  type        = string
}

variable "resource_group_name" {
  description = "Existing resource group"
  type        = string
}

variable "db_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers"
  type        = string
}

variable "db_private_dns_zone_id" {
  description = "Private DNS zone privatelink.postgres.database.azure.com linked to the VNet"
  type        = string
}

variable "db_sku" {
  description = "PostgreSQL Flexible Server SKU"
  type        = string
  default     = "GP_Standard_D2ds_v5"
}

variable "db_storage_mb" {
  description = "Database storage"
  type        = number
  default     = 65536
}

variable "secret_expiration_date" {
  description = "RFC 3339 expiry for the database URL secret; rotate before it passes"
  type        = string
}

variable "aks_oidc_issuer_url" {
  description = "AKS cluster OIDC issuer URL (az aks show --query oidcIssuerProfile.issuerUrl)"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace of the service"
  type        = string
  default     = "self-healing"
}

variable "service_account" {
  description = "Kubernetes service account of the service"
  type        = string
  default     = "self-healing-infrastructure-agents"
}

variable "remediation_scopes" {
  description = "Map of name => Azure scope ID the service may change through Terraform remediation"
  type        = map(string)
  default     = {}
}

variable "remediation_role" {
  description = "Role granted on each remediation scope"
  type        = string
  default     = "Contributor"
}

variable "stacks_quota_gb" {
  description = "Quota of the terraform-stacks file share"
  type        = number
  default     = 100
}

variable "audit_retention_days" {
  description = "Immutability period for audit chains"
  type        = number
  default     = 2555
}

variable "tags" {
  description = "Tags applied to every resource"
  type        = map(string)
  default     = { "app.kubernetes.io/part-of" = "self-healing-infrastructure-agents" }
}
