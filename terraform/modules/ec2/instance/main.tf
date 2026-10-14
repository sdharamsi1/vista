# One scenario instance: private, IMDSv2, encrypted, and role-less unless config says otherwise.
locals {
  subnet      = var.subnets[var.config.subnet]
  create_role = length(var.config.policy_statements) > 0 || length(var.config.managed_policy_arns) > 0
}

# Inbound only on config.ingress, from the listed CIDRs or security groups.
resource "aws_security_group" "this" {
  tags        = { Name = var.name }
  name        = var.name
  description = "Instance access"
  vpc_id      = local.subnet.vpc_id

  dynamic "ingress" {
    for_each = var.config.ingress
    content {
      description     = ingress.value.description
      from_port       = ingress.value.port
      to_port         = ingress.value.port
      protocol        = "tcp"
      cidr_blocks     = ingress.value.cidrs
      security_groups = ingress.value.source_security_group_ids
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  count              = local.create_role ? 1 : 0
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "this" {
  count = length(var.config.policy_statements) > 0 ? 1 : 0
  name  = var.config.policy_name
  role  = aws_iam_role.this[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      for statement in var.config.policy_statements : {
        Effect   = "Allow"
        Action   = statement.actions
        Resource = statement.resources
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each   = toset(var.config.managed_policy_arns)
  role       = aws_iam_role.this[0].name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "this" {
  count = local.create_role ? 1 : 0
  name  = var.name
  role  = aws_iam_role.this[0].name
}

# No key pair, so nobody can SSH in. User data only runs a static web server when app_port is set.
resource "aws_instance" "this" {
  tags                        = { Name = var.name }
  ami                         = var.ami
  instance_type               = coalesce(var.config.instance_type, var.instance_type)
  subnet_id                   = local.subnet.id
  associate_public_ip_address = local.subnet.public_ip
  vpc_security_group_ids      = concat([aws_security_group.this.id], var.config.extra_security_group_ids)
  disable_api_termination     = false
  iam_instance_profile        = local.create_role ? aws_iam_instance_profile.this[0].name : null
  user_data                   = var.config.app_port == null ? null : templatefile("${path.module}/web.sh.tftpl", { port = var.config.app_port })

  metadata_options {
    http_tokens = var.config.imds_tokens
  }

  root_block_device {
    encrypted = var.config.encrypted
  }
}

# count, not for_each: target group ARNs are unknown until the load balancer exists.
resource "aws_lb_target_group_attachment" "this" {
  count            = length(var.config.target_group_arns)
  target_group_arn = var.config.target_group_arns[count.index]
  target_id        = aws_instance.this.id
  port             = var.config.app_port
}
