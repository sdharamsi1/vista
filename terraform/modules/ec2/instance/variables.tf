variable "name" {
  description = "Name for the instance's security group, role, and instance profile."
  type        = string
}

variable "ami" {
  description = "AMI ID to launch."
  type        = string
}

variable "instance_type" {
  description = "Instance type used when config.instance_type is unset."
  type        = string
}

variable "subnets" {
  description = "Subnet key -> subnet ID, its VPC, and whether instances there get a public IP."
  type = map(object({
    id        = string
    vpc_id    = string
    public_ip = bool
  }))
}

variable "config" {
  description = "How this scenario differs from the hardened default; anything unset stays hardened."
  type = object({
    subnet        = optional(string, "private")
    instance_type = optional(string)
    ingress = optional(list(object({
      port                      = number
      cidrs                     = optional(list(string), [])
      source_security_group_ids = optional(list(string), [])
      description               = optional(string)
    })), [])
    extra_security_group_ids = optional(list(string), [])
    imds_tokens              = optional(string, "required")
    encrypted                = optional(bool, true)
    managed_policy_arns      = optional(list(string), [])
    policy_name              = optional(string, "permissions")
    policy_statements = optional(list(object({
      actions   = list(string)
      resources = list(string)
    })), [])
    app_port          = optional(number)
    target_group_arns = optional(list(string), [])
  })

  validation {
    condition     = contains(keys(var.subnets), var.config.subnet)
    error_message = "config.subnet must be one of the subnet keys."
  }
}
