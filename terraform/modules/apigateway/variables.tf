variable "name" {
  description = "Prefix for every resource name in this module."
  type        = string
}

variable "tiers" {
  description = "Scenario tiers to deploy (controlled, realistic)."
  type        = set(string)
}

variable "office_cidr" {
  description = "Office network that the internal admin API's resource policy allows."
  type        = string
}
