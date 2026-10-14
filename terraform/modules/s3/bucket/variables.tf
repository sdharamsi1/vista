variable "name" {
  description = "Bucket name; must be globally unique."
  type        = string
}

variable "log_bucket" {
  description = "Bucket that receives server access logs."
  type        = string
}

variable "config" {
  description = "How this scenario differs from the hardened default; anything unset stays hardened."
  type = object({
    public_acl  = optional(bool, false)
    sse         = optional(string, "aws:kms")
    versioning  = optional(bool, true)
    logging     = optional(bool, true)
    object_lock = optional(bool, false)
    website     = optional(bool, false)
    tls_only    = optional(bool, true)
    cors = optional(object({
      origins = list(string)
      methods = list(string)
    }))
    policy_statements = optional(list(object({
      actions   = list(string)
      prefix    = optional(string, "")
      condition = optional(map(map(string)), {})
    })), [])
  })
  default = {}

  validation {
    condition     = contains(["aws:kms", "AES256"], var.config.sse)
    error_message = "config.sse must be aws:kms or AES256."
  }
}
