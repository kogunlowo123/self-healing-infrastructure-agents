output "service_account_role_arn" {
  description = "Annotate the service account with eks.amazonaws.com/role-arn = this value"
  value       = aws_iam_role.heal.arn
}

output "database_url_secret_name" {
  description = "Secrets Manager secret synced to Kubernetes as DATABASE_URL"
  value       = aws_secretsmanager_secret.database_url.name
}

output "alertmanager_token_secret_name" {
  description = "Secrets Manager secret the security team populates with the webhook credential"
  value       = aws_secretsmanager_secret.alertmanager_token.name
}

output "kms_key_arn" {
  description = "KMS key that encrypts the database, secrets, audit bucket, stacks volume and alarm topic"
  value       = aws_kms_key.heal.arn
}

output "audit_bucket" {
  description = "Object Lock (compliance mode) bucket receiving audit chains"
  value       = aws_s3_bucket.audit.bucket
}

output "stacks_file_system_id" {
  description = "EFS file system for the terraform-stacks PersistentVolume (EFS CSI driver)"
  value       = aws_efs_file_system.stacks.id
}

output "stacks_access_point_id" {
  description = "EFS access point (uid/gid 10001) to reference in the PersistentVolume volumeHandle"
  value       = aws_efs_access_point.stacks.id
}

output "alarms_topic_arn" {
  description = "Point CloudWatch alarm actions here; add it to heal.snsTopicArns"
  value       = aws_sns_topic.alarms.arn
}
