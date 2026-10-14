terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.70" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = var.tags }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name            = var.name
  account_id      = data.aws_caller_identity.current.account_id
  oidc_issuer     = trimprefix(var.eks_oidc_issuer_url, "https://")
  service_account = "system:serviceaccount:${var.namespace}:${var.service_account}"
}

# ---------------------------------------------------------------- encryption

data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }
  statement {
    sid       = "CloudWatchAlarmsPublishToEncryptedTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "heal" {
  description             = "${local.name}: database, secrets, audit, stacks and alarm topic encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "heal" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.heal.key_id
}

# ------------------------------------------------------------------ database

resource "aws_db_subnet_group" "heal" {
  name       = local.name
  subnet_ids = var.private_subnet_ids
}

resource "aws_security_group" "db" {
  name        = "${local.name}-db"
  description = "PostgreSQL access from the EKS cluster only"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_cluster" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = var.cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "EKS nodes"
}

resource "aws_db_parameter_group" "heal" {
  name   = local.name
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
}

resource "random_password" "db" {
  length  = 40
  special = false
}

resource "aws_db_instance" "heal" {
  identifier                          = local.name
  engine                              = "postgres"
  engine_version                      = "16.4"
  instance_class                      = var.db_instance_class
  allocated_storage                   = var.db_allocated_storage_gb
  max_allocated_storage               = var.db_allocated_storage_gb * 4
  storage_type                        = "gp3"
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.heal.arn
  db_name                             = "heal"
  username                            = "heal"
  password                            = random_password.db.result
  db_subnet_group_name                = aws_db_subnet_group.heal.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  parameter_group_name                = aws_db_parameter_group.heal.name
  multi_az                            = true
  publicly_accessible                 = false
  backup_retention_period             = 14
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${local.name}-final"
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.heal.arn
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}

resource "aws_secretsmanager_secret" "database_url" {
  name       = "${local.name}-database-url"
  kms_key_id = aws_kms_key.heal.arn
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = format(
    "postgresql+asyncpg://heal:%s@%s:%d/heal?ssl=require",
    random_password.db.result, aws_db_instance.heal.address, aws_db_instance.heal.port,
  )
}

# The value is set by the security team (never in Terraform state); the
# container lets External Secrets and IAM policies reference it by name.
resource "aws_secretsmanager_secret" "alertmanager_token" {
  name        = "${local.name}-alertmanager-token"
  description = "Bearer credential Alertmanager presents to the self-healing webhook"
  kms_key_id  = aws_kms_key.heal.arn
}

# ------------------------------------------------------------- audit (WORM)

resource "aws_s3_bucket" "audit" {
  bucket              = "${local.name}-audit-${local.account_id}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.heal.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit_bucket.json
}

# ---------------------------------------------- Terraform stacks (EFS, RWX)

resource "aws_efs_file_system" "stacks" {
  creation_token   = "${local.name}-stacks"
  encrypted        = true
  kms_key_id       = aws_kms_key.heal.arn
  performance_mode = "generalPurpose"
  throughput_mode  = "elastic"
  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

resource "aws_efs_backup_policy" "stacks" {
  file_system_id = aws_efs_file_system.stacks.id
  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_security_group" "efs" {
  name        = "${local.name}-efs"
  description = "NFS access to the Terraform stacks volume from the EKS cluster only"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "efs_from_cluster" {
  security_group_id            = aws_security_group.efs.id
  referenced_security_group_id = var.cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  description                  = "EKS nodes (EFS CSI driver)"
}

resource "aws_efs_mount_target" "stacks" {
  for_each        = toset(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.stacks.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "stacks" {
  file_system_id = aws_efs_file_system.stacks.id
  posix_user {
    uid = 10001
    gid = 10001
  }
  root_directory {
    path = "/stacks"
    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "0750"
    }
  }
}

# ------------------------------------------- CloudWatch alarm delivery (SNS)

resource "aws_sns_topic" "alarms" {
  name              = "${local.name}-alarms"
  kms_master_key_id = aws_kms_key.heal.arn
  # The service accepts only SHA256 (version 2) signatures.
  signature_version = 2
}

data "aws_iam_policy_document" "alarms_topic" {
  statement {
    sid       = "CloudWatchAlarmsFromThisAccount"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alarms.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alarms" {
  arn    = aws_sns_topic.alarms.arn
  policy = data.aws_iam_policy_document.alarms_topic.json
}

resource "aws_sns_topic_subscription" "service" {
  topic_arn              = aws_sns_topic.alarms.arn
  protocol               = "https"
  endpoint               = "${trimsuffix(var.public_url, "/")}/v1/alerts/cloudwatch"
  endpoint_auto_confirms = false
  raw_message_delivery   = false
}

# ---------------------------------------------------- workload identity (IRSA)

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:sub"
      values   = [local.service_account]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# Terraform remediation runs with this role. Its reach is bounded twice: the
# managed policies the platform team attaches for the stacks it may change,
# and a permissions boundary that caps them.
resource "aws_iam_role" "heal" {
  name                 = local.name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  permissions_boundary = var.remediation_permissions_boundary_arn
}

data "aws_iam_policy_document" "heal" {
  statement {
    sid       = "ShipAuditChains"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
  }
  statement {
    sid       = "EncryptAudit"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.heal.arn]
  }
}

resource "aws_iam_role_policy" "heal" {
  role   = aws_iam_role.heal.id
  policy = data.aws_iam_policy_document.heal.json
}

resource "aws_iam_role_policy_attachment" "remediation" {
  for_each   = toset(var.remediation_policy_arns)
  role       = aws_iam_role.heal.name
  policy_arn = each.value
}
