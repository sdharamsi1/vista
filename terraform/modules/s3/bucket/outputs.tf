output "bucket_name" {
  description = "Bucket name that Vista cites in its findings."
  value       = aws_s3_bucket.this.id
}
