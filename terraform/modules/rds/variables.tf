variable "name" {
  description = "Prefix for every resource name in this module."
  type        = string
}
variable "instance_class" {
  description = "Instance class for every scenario."
  type        = string
  default     = "db.t4g.micro"
}
variable "cidr_block" {
  description = "CIDR block for the scenario VPC."
  type        = string
  default     = "10.81.0.0/16"
}

variable "tiers" {
  description = "Scenario tiers to deploy (controlled, realistic)."
  type        = set(string)
}

variable "office_cidr" {
  description = "Office network; the BI database allows one address in it."
  type        = string
}
