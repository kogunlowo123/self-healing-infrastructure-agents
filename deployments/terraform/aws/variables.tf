variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "self-healing-agents"
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "public_url" {
  description = "External HTTPS URL of the service (SNS delivers alarms to <public_url>/v1/alerts/cloudwatch)"
  type        = string
  validation {
    condition     = startswith(var.public_url, "https://")
    error_message = "SNS delivers alarms over HTTPS only."
  }
}

variable "vpc_id" {
  description = "VPC hosting the EKS cluster"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the database and EFS mount targets (at least two AZs)"
  type        = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Provide subnets in at least two availability zones."
  }
}

variable "cluster_security_group_id" {
  description = "Security group of the EKS nodes allowed to reach PostgreSQL and EFS"
  type        = string
}

variable "eks_oidc_provider_arn" {
  description = "ARN of the EKS cluster IAM OIDC provider"
  type        = string
}

variable "eks_oidc_issuer_url" {
  description = "EKS cluster OIDC issuer URL"
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

variable "remediation_policy_arns" {
  description = "Managed policies granting the access Terraform remediation needs for the stacks in scope"
  type        = list(string)
  default     = []
}

variable "remediation_permissions_boundary_arn" {
  description = "Permissions boundary capping everything the service role can ever do"
  type        = string
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage_gb" {
  description = "Initial database storage"
  type        = number
  default     = 50
}

variable "audit_retention_days" {
  description = "Object Lock compliance retention for audit chains"
  type        = number
  default     = 2555 # 7 years
}

variable "tags" {
  description = "Tags applied to every resource"
  type        = map(string)
  default     = { "app.kubernetes.io/part-of" = "self-healing-infrastructure-agents" }
}
