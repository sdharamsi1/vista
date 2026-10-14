variable "name" {
  description = "Identifier for the instance and name for its security group, parameter group, and role."
  type        = string
}

variable "engines" {
  description = "Engine -> version and parameter group family to launch."
  type = map(object({
    version = string
    family  = string
  }))
}

variable "instance_class" {
  description = "Instance class to launch."
  type        = string
}

variable "vpc_id" {
  description = "VPC for the security group."
  type        = string
}

variable "public_subnet_group" {
  description = "DB subnet group with an Internet gateway route, used when config.public is true."
  type        = string
}

variable "private_subnet_group" {
  description = "DB subnet group with no Internet route, used otherwise."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer-managed key for storage encryption, used when config.encrypted is true."
  type        = string
}

variable "config" {
  description = "How this scenario differs from the hardened default; anything unset stays hardened."
  type = object({
    engine = optional(string, "postgres")
    public = optional(bool, false)
    ingress = optional(object({
      cidrs              = optional(list(string), [])
      security_group_ids = optional(list(string), [])
      description        = optional(string)
    }))
    encrypted        = optional(bool, true)
    force_ssl        = optional(bool, true)
    iam_auth         = optional(bool, true)
    managed_password = optional(bool, true)
    backup_retention = optional(number, 7)
    log_exports      = optional(bool, true)
    associated_role = optional(object({
      feature = string
      statements = list(object({
        actions   = list(string)
        resources = list(string)
      }))
    }))
    snapshot = optional(object({
      name            = string
      shared_accounts = list(string)
    }))
  })
  default = {}

  validation {
    condition     = contains(["postgres", "mysql"], var.config.engine)
    error_message = "config.engine must be postgres or mysql."
  }
}
