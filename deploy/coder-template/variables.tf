variable "project" {
  type        = string
  description = "GCP project ID"
}

variable "region" {
  type        = string
  description = "GCP region"
  default     = "us-central1"
}

variable "zone" {
  type        = string
  description = "GCP zone"
  default     = "us-central1-a"
}

variable "gar_region" {
  type        = string
  description = "Region of the Artifact Registry repository"
  default     = "us-central1"
}

variable "machine_type" {
  type        = string
  description = "GCP machine type"
  default     = "n2-standard-4"
}

variable "disk_size_gb" {
  type        = number
  description = "Persistent data disk size in GB"
  default     = 50
}

variable "container_image" {
  type        = string
  description = "vigil workspace image from GAR, e.g. us-central1-docker.pkg.dev/project/vigil/workspace:latest"
}

variable "service_account_email" {
  type        = string
  description = "GCP service account email for the workspace VM"
}

variable "github_app_id" {
  type        = string
  description = "Coder external auth GitHub app ID"
  default     = "primary-github"
}

variable "codeserver" {
  type    = string
  default = "true"
}

variable "vigil_repo" {
  type    = string
  default = "https://github.com/VectorInstitute/vigil.git"
}

variable "vigil_branch" {
  type    = string
  default = "main"
}
