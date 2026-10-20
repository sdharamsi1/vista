# Vista

Vista is a research tool built to evaluate how effectively large language models (LLMs) assess the
attack surface of AWS resources. It collects factual AWS configuration for EC2, S3, API Gateway and
RDS, sends it to an Amazon Bedrock model with a facts-only prompt, and validates the structured
review the model returns.

Vista's results are compared with Prowler, a deterministic rule-based scanner. Both are scored
against the same facts-only answer key: 40 Terraform-deployed scenarios mapped to AWS Security Hub
Foundational Security Best Practices (FSBP) controls and their published severities.
