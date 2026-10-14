variable "name" {
  description = "Prefix for every resource name in this module."
  type        = string
}

variable "tiers" {
  description = "Scenario tiers to deploy (controlled, realistic)."
  type        = set(string)
}

variable "office_cidr" {
  description = "Office network that the admin bastion allows SSH from."
  type        = string
}

variable "instance_type" {
  description = "Instance type for scenarios that don't set their own."
  type        = string
  default     = "t4g.nano"
}

variable "prod_cidr" {
  description = "CIDR block for the production VPC."
  type        = string
  default     = "10.80.0.0/16"
}

variable "legacy_cidr" {
  description = "CIDR block for the legacy VPC."
  type        = string
  default     = "10.90.0.0/16"
}
