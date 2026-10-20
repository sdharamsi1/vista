# ground-truth.json is the facts-only answer key: each scenario's condition, FSBP coverage, and
# published FSBP control severities. Every scenario starts from the module's hardened default
# (private subnet, IMDSv2, encrypted root volume, no role, no inbound rules) and lists only what
# differs.
#
# controlled: one setting changed per instance from that default.
# realistic:  instances that share a load balancer, NAT, and security groups the way a real
#             account does.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # Private batch worker with an unencrypted root volume.
    "ec2-01" = {
      tier      = "controlled"
      name      = "reporting-worker"
      encrypted = false
    }
    # Marketing site in the public subnet serving HTTP on 80; TCP 80 and 443 from 0.0.0.0/0; no role.
    "ec2-02" = {
      tier     = "controlled"
      name     = "marketing-site"
      subnet   = "public"
      app_port = 80
      ingress = [
        { port = 80, cidrs = ["0.0.0.0/0"], description = "HTTP" },
        { port = 443, cidrs = ["0.0.0.0/0"], description = "HTTPS" },
      ]
    }
    # Private image resizer with IMDSv1 accepted and a role that reads the uploads bucket.
    "ec2-03" = {
      tier        = "controlled"
      name        = "image-resizer"
      imds_tokens = "optional"
      policy_statements = [{
        actions   = ["s3:GetObject", "s3:ListBucket"]
        resources = [aws_s3_bucket.media.arn, "${aws_s3_bucket.media.arn}/*"]
      }]
    }
    # Private CI runner whose role allows iam:AttachRolePolicy and iam:PutRolePolicy on *.
    "ec2-04" = {
      tier = "controlled"
      name = "ci-runner"
      policy_statements = [{
        actions   = ["iam:AttachRolePolicy", "iam:PutRolePolicy"]
        resources = ["*"]
      }]
    }
    # Bastion in the legacy VPC with TCP 22 from 0.0.0.0/0 and AdministratorAccess on its role.
    "ec2-05" = {
      tier                = "controlled"
      name                = "legacy-bastion"
      subnet              = "legacy"
      ingress             = [{ port = 22, cidrs = ["0.0.0.0/0"], description = "SSH - temporary for migration" }]
      managed_policy_arns = ["arn:${local.partition}:iam::aws:policy/AdministratorAccess"]
    }

    # ---------- realistic ----------

    # Storefront behind the HTTPS load balancer; TCP 8080 only from the ALB security group.
    "ec2-06" = {
      tier                     = "realistic"
      name                     = "storefront-web"
      instance_type            = "t4g.micro"
      app_port                 = 8080
      target_group_arns        = [local.storefront_target_group]
      ingress                  = [{ port = 8080, source_security_group_ids = [local.alb_security_group_id], description = "From storefront ALB" }]
      extra_security_group_ids = [aws_security_group.monitoring.id]
      managed_policy_arns      = [local.ssm_core]
    }
    # Orders API behind the same load balancer (/api/*), with IMDSv1 accepted and a role that allows
    # secretsmanager:GetSecretValue and secretsmanager:DescribeSecret on *.
    "ec2-07" = {
      tier                     = "realistic"
      name                     = "orders-api"
      subnet                   = "private_b"
      instance_type            = "t4g.small"
      imds_tokens              = "optional"
      app_port                 = 8080
      target_group_arns        = [local.orders_target_group]
      ingress                  = [{ port = 8080, source_security_group_ids = [local.alb_security_group_id], description = "From storefront ALB" }]
      extra_security_group_ids = [aws_security_group.monitoring.id]
      managed_policy_arns      = [local.ssm_core]
      policy_statements = [
        {
          actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
          resources = ["*"]
        },
        {
          actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem"]
          resources = ["arn:${local.partition}:dynamodb:${local.region}:${local.account_id}:table/orders"]
        },
      ]
    }
    # Admin bastion in the ops subnet with a public IP; TCP 22 only from the office CIDR.
    "ec2-08" = {
      tier                = "realistic"
      name                = "admin-bastion"
      subnet              = "ops"
      ingress             = [{ port = 22, cidrs = [var.office_cidr], description = "Office VPN" }]
      managed_policy_arns = [local.ssm_core]
    }
    # Metrics collector in the ops subnet with a public IP; its security group allows TCP 9100 from
    # 0.0.0.0/0, and the ops network ACL denies inbound TCP 9100 (rule 90).
    "ec2-09" = {
      tier    = "realistic"
      name    = "metrics-collector"
      subnet  = "ops"
      ingress = [{ port = 9100, cidrs = ["0.0.0.0/0"], description = "Prometheus scrape" }]
    }
    # Private Jupyter notebook with TCP 8888 from 10.0.0.0/8 and a role that allows s3:* on *.
    "ec2-10" = {
      tier                = "realistic"
      name                = "analytics-notebook"
      instance_type       = "t4g.small"
      ingress             = [{ port = 8888, cidrs = ["10.0.0.0/8"], description = "Jupyter" }]
      managed_policy_arns = [local.ssm_core]
      policy_name         = "data-access"
      policy_statements = [{
        actions   = ["s3:*"]
        resources = ["*"]
      }]
    }
    # Private queue worker with the monitoring security group and a role limited to one SQS queue.
    "ec2-11" = {
      tier                     = "realistic"
      name                     = "queue-worker"
      subnet                   = "private_b"
      extra_security_group_ids = [aws_security_group.monitoring.id]
      managed_policy_arns      = [local.ssm_core]
      policy_statements = [{
        actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        resources = ["arn:${local.partition}:sqs:${local.region}:${local.account_id}:order-events"]
      }]
    }
  }
}
