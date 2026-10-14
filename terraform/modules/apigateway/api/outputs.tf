output "api_id" {
  description = "REST API ID that Vista cites in its findings."
  value       = aws_api_gateway_rest_api.this.id
}
