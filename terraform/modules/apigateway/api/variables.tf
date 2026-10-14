variable "name" {
  description = "Name for the API and its integration role."
  type        = string
}

variable "region" {
  description = "Region the API is deployed in, used to build the DynamoDB integration URI."
  type        = string
}

variable "partition" {
  description = "AWS partition, used to build the DynamoDB integration URI."
  type        = string
}

variable "table_name" {
  description = "DynamoDB table the routes read and write."
  type        = string
}

variable "table_arn" {
  description = "ARN of the DynamoDB table, the only resource the integration role can touch."
  type        = string
}

variable "web_acl_arn" {
  description = "Web ACL attached to the stage when config.waf is true."
  type        = string
}

variable "user_pool_arn" {
  description = "Cognito user pool for the authorizer when config.authorization is COGNITO_USER_POOLS."
  type        = string
  default     = null
}

variable "config" {
  description = "How this scenario differs from the hardened default; anything unset stays hardened."
  type = object({
    authorization        = optional(string, "AWS_IAM")
    methods              = optional(list(string), ["GET"])
    api_key_required     = optional(bool, false)
    usage_plan           = optional(bool, false)
    allowed_source_cidrs = optional(list(string), [])
    health_route         = optional(bool, false)
    access_logs          = optional(bool, true)
    data_trace           = optional(bool, false)
    waf                  = optional(bool, true)
    throttling           = optional(bool, true)
  })
  default = {}

  validation {
    condition     = contains(["AWS_IAM", "NONE", "COGNITO_USER_POOLS"], var.config.authorization)
    error_message = "config.authorization must be AWS_IAM, NONE, or COGNITO_USER_POOLS."
  }
}
