variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "self-healing-agents"
}

variable "project_id" {
  description = "GCP project"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "filestore_zone" {
  description = "Zone of the BASIC_HDD Filestore instance backing the terraform-stacks volume"
  type        = string
}

variable "network_id" {
  description = "VPC network self link with private services access configured"
  type        = string
}

variable "cluster_pod_cidr" {
  description = "GKE pod CIDR allowed to mount the stacks share"
  type        = string
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-2-7680"
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

variable "remediation_roles" {
  description = "Project roles granted for the stacks Terraform remediation may change"
  type        = list(string)
  default     = []
}

variable "audit_retention_days" {
  description = "Bucket retention for audit chains"
  type        = number
  default     = 2555
}

variable "lock_audit_retention" {
  description = "Permanently lock the retention policy (irreversible)"
  type        = bool
  default     = false
}
