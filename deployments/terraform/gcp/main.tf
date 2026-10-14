terraform {
  required_version = ">= 1.7.0"
  required_providers {
    google      = { source = "hashicorp/google", version = "~> 6.8" }
    google-beta = { source = "hashicorp/google-beta", version = "~> 6.8" }
    random      = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

locals {
  name = var.name
}

# ---------------------------------------------------------------- encryption

resource "google_kms_key_ring" "heal" {
  name     = local.name
  location = var.region
}

resource "google_kms_crypto_key" "heal" {
  name            = "${local.name}-data"
  key_ring        = google_kms_key_ring.heal.id
  rotation_period = "7776000s" # 90 days
  lifecycle {
    prevent_destroy = true
  }
}

data "google_project" "current" {}

resource "google_project_service_identity" "sql" {
  provider = google-beta
  project  = var.project_id
  service  = "sqladmin.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "sql" {
  crypto_key_id = google_kms_crypto_key.heal.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.sql.email}"
}

resource "google_kms_crypto_key_iam_member" "storage" {
  crypto_key_id = google_kms_crypto_key.heal.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.current.number}@gs-project-accounts.iam.gserviceaccount.com"
}

# ------------------------------------------------------------------ database

resource "random_password" "db" {
  length  = 40
  special = false
}

resource "google_sql_database_instance" "heal" {
  name                = local.name
  database_version    = "POSTGRES_16"
  region              = var.region
  encryption_key_name = google_kms_crypto_key.heal.id
  deletion_protection = true
  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"
    disk_autoresize   = true
    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = var.network_id
      ssl_mode                                      = "ENCRYPTED_ONLY"
      enable_private_path_for_google_cloud_services = true
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = 14
      }
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
  }
  depends_on = [google_kms_crypto_key_iam_member.sql]
}

resource "google_sql_database" "heal" {
  name     = "heal"
  instance = google_sql_database_instance.heal.name
}

resource "google_sql_user" "heal" {
  name     = "heal"
  instance = google_sql_database_instance.heal.name
  password = random_password.db.result
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "${local.name}-database-url"
  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.database_url.id
  secret_data = format(
    "postgresql+asyncpg://heal:%s@%s:5432/heal?ssl=require",
    random_password.db.result, google_sql_database_instance.heal.private_ip_address,
  )
}

# ------------------------------------------------------------- audit (WORM)

resource "google_storage_bucket" "audit" {
  name                        = "${local.name}-audit-${var.project_id}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
  retention_policy {
    retention_period = var.audit_retention_days * 86400
    is_locked        = var.lock_audit_retention
  }
  encryption {
    default_kms_key_name = google_kms_crypto_key.heal.id
  }
  depends_on = [google_kms_crypto_key_iam_member.storage]
}

# ---------------------------------------------- Terraform stacks (Filestore)

resource "google_filestore_instance" "stacks" {
  name     = "${local.name}-stacks"
  location = var.filestore_zone
  tier     = "BASIC_HDD"
  file_shares {
    name        = "stacks"
    capacity_gb = 1024
    nfs_export_options {
      ip_ranges   = [var.cluster_pod_cidr]
      access_mode = "READ_WRITE"
      squash_mode = "ROOT_SQUASH"
      anon_uid    = 10001
      anon_gid    = 10001
    }
  }
  networks {
    network = var.network_id
    modes   = ["MODE_IPV4"]
  }
}

# --------------------------------------------- workload identity (GKE)

resource "google_service_account" "heal" {
  account_id   = substr(local.name, 0, 30)
  display_name = "Self-healing infrastructure agents"
}

resource "google_service_account_iam_member" "workload_identity" {
  service_account_id = google_service_account.heal.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${var.service_account}]"
}

resource "google_storage_bucket_iam_member" "audit_writer" {
  bucket = google_storage_bucket.audit.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.heal.email}"
}

# Terraform remediation scope: project-level roles the platform team delegates.
resource "google_project_iam_member" "remediation" {
  for_each = toset(var.remediation_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.heal.email}"
}
