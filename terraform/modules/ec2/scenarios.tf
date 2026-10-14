# Expected ratings are in ground-truth.json. Every scenario starts hardened (private subnet, IMDSv2,
# encrypted root volume, no role, no inbound rules) and lists only what differs.
#
# controlled: the single-flaw severity ladder, one setting changed per instance.
# realistic:  expected, ambiguous, and messy cases that share a load balancer, NAT, and security
#             groups the way a real account does.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # LOW: private batch worker, but its root volume is unencrypted.
    "ec2-01" = {
      tier      = "controlled"
      name      = "reporting-worker"
      encrypted = false
    }
    # MEDIUM: public marketing site serving HTTP on 80, with 80 and 443 open to the world, no role.
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
    # MEDIUM: private image resizer with IMDSv1 and a role that reads the uploads bucket.
    "ec2-03" = {
      tier        = "controlled"
      name        = "image-resizer"
      imds_tokens = "optional"
      policy_statements = [{
        actions   = ["s3:GetObject", "s3:ListBucket"]
        resources = [aws_s3_bucket.media.arn, "${aws_s3_bucket.media.arn}/*"]
      }]
    }
    # HIGH: private CI runner whose role can attach any policy to any role, including itself.
    "ec2-04" = {
      tier = "controlled"
      name = "ci-runner"
      policy_statements = [{
        actions   = ["iam:AttachRolePolicy", "iam:PutRolePolicy"]
        resources = ["*"]
      }]
    }
    # CRITICAL: old bastion in the legacy VPC with SSH open to the world and a leftover admin role.
    "ec2-05" = {
      tier                = "controlled"
      name                = "legacy-bastion"
      subnet              = "legacy"
      ingress             = [{ port = 22, cidrs = ["0.0.0.0/0"], description = "SSH - temporary for migration" }]
      managed_policy_arns = ["arn:${local.partition}:iam::aws:policy/AdministratorAccess"]
    }

    # ---------- realistic ----------

    # EXPECTED: storefront behind the HTTPS load balancer; only the ALB can reach it.
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
    # HIGH: orders API reached from the Internet through the ALB (/api/*), with IMDSv1 and a role
    # that can read every secret in the account.
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
    # AMBIGUOUS: public admin bastion, but SSH is limited to the office network.
    "ec2-08" = {
      tier                = "realistic"
      name                = "admin-bastion"
      subnet              = "ops"
      ingress             = [{ port = 22, cidrs = [var.office_cidr], description = "Office VPN" }]
      managed_policy_arns = [local.ssm_core]
    }
    # EXPECTED: public metrics collector whose security group opens 9100 to the world, but the
    # ops subnet's network ACL denies 9100 inbound, so nothing outside can reach it.
    "ec2-09" = {
      tier    = "realistic"
      name    = "metrics-collector"
      subnet  = "ops"
      ingress = [{ port = 9100, cidrs = ["0.0.0.0/0"], description = "Prometheus scrape" }]
    }
    # HIGH: private Jupyter notebook open to the whole 10.0.0.0/8 range, with a role that was
    # given s3:* on everything to unblock an analyst.
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
    # EXPECTED: private queue worker scoped to one SQS queue, reachable only by the monitoring SG.
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
