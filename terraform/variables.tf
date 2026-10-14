variable "region" {
  description = "Region to deploy the scenarios into; scan only this region with Vista."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Company-style prefix for every resource name. Avoid anything that hints at testing."
  type        = string
  default     = "brightpath"
}

variable "tiers" {
  description = "Scenario tiers to deploy: controlled (single-flaw ladder) and/or realistic (expected, ambiguous, and messy cases)."
  type        = set(string)
  default     = ["controlled", "realistic"]

  validation {
    condition     = length(var.tiers) > 0 && length(setsubtract(var.tiers, ["controlled", "realistic"])) == 0
    error_message = "tiers must be a non-empty subset of [\"controlled\", \"realistic\"]."
  }
}

variable "office_cidr" {
  description = "Stand-in for the company's office network. Defaults to TEST-NET-3 (RFC 5737), which is not routable."
  type        = string
  default     = "203.0.113.0/24"
}

variable "enable_ec2" {
  description = "Deploy the EC2 scenarios."
  type        = bool
  default     = true
}

variable "enable_s3" {
  description = "Deploy the S3 scenarios."
  type        = bool
  default     = false
}

variable "enable_apigateway" {
  description = "Deploy the API Gateway scenarios."
  type        = bool
  default     = false
}

variable "enable_rds" {
  description = "Deploy the RDS scenarios."
  type        = bool
  default     = false
}

