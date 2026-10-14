output "instance_id" {
  description = "Instance ID that Vista cites in its findings."
  value       = aws_instance.this.id
}
