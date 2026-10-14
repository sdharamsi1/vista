output "identifier" {
  description = "Instance identifier, or snapshot identifier when the scenario has a snapshot, that Vista cites in its findings."
  value       = var.config.snapshot == null ? aws_db_instance.this.identifier : aws_db_snapshot.this[0].db_snapshot_identifier
}

output "instance_identifier" {
  description = "DB instance identifier, for targets such as an RDS Proxy."
  value       = aws_db_instance.this.identifier
}

output "master_secret_arn" {
  description = "Secrets Manager ARN of the managed master password, or null when the password is static."
  value       = one(aws_db_instance.this.master_user_secret[*].secret_arn)
}
