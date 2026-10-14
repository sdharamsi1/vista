variable "name" {
  description = "Prefix for every resource name in this module."
  type        = string
}

variable "tiers" {
  description = "Scenario tiers to deploy (controlled, realistic)."
  type        = set(string)
}

variable "org_id" {
  description = "Organization ID used in the org-wide access scenario; it is not validated by AWS."
  type        = string
  default     = "o-a1b2c3d4e5"
}
