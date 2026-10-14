terraform {
  # 1.11+ for write-only arguments and ephemeral resources (the legacy DB's static password).
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.68.0"
    }
    # Self-signed certificate for the storefront load balancer's HTTPS listener.
    tls = {
      source  = "hashicorp/tls"
      version = "4.4.1"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = { "managed-by" = "terraform" }
  }
}
