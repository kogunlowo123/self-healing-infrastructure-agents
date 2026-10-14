output "gcp_service_account" {
  description = "Annotate the service account with iam.gke.io/gcp-service-account = this value"
  value       = google_service_account.heal.email
}

output "database_url_secret" {
  description = "Secret Manager secret synced to Kubernetes as DATABASE_URL"
  value       = google_secret_manager_secret.database_url.secret_id
}

output "audit_bucket" {
  description = "Retention-locked bucket receiving audit chains"
  value       = google_storage_bucket.audit.name
}

output "stacks_share" {
  description = "Filestore export backing the terraform-stacks PersistentVolume (NFS)"
  value       = "${google_filestore_instance.stacks.networks[0].ip_addresses[0]}:/${google_filestore_instance.stacks.file_shares[0].name}"
}
