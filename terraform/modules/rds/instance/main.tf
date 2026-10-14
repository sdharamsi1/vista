# One scenario instance: private, encrypted with a customer-managed key, TLS enforced, IAM and
# Secrets Manager authentication, backups, and log exports, unless config says otherwise.
# Deletion protection is always off so terraform destroy works in one step.
locals {
  create_role = var.config.associated_role != null

  # What differs between engines: port, the parameter that forces TLS, and exportable logs.
  engine_settings = {
    postgres = { port = 5432, tls_parameter = "rds.force_ssl", tls_on = "1", tls_off = "0", logs = ["postgresql", "upgrade"] }
    mysql    = { port = 3306, tls_parameter = "require_secure_transport", tls_on = "ON", tls_off = "OFF", logs = ["error", "slowquery"] }
  }
  engine      = local.engine_settings[var.config.engine]
  log_exports = var.config.log_exports ? local.engine.logs : []
}

# Inbound only on the database port from config.ingress. No egress rules: a database does not
# initiate connections.
resource "aws_security_group" "this" {
  tags        = { Name = var.name }
  name        = var.name
  description = "Database access"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.config.ingress == null ? [] : [var.config.ingress]
    content {
      description     = ingress.value.description
      from_port       = local.engine.port
      to_port         = local.engine.port
      protocol        = "tcp"
      cidr_blocks     = ingress.value.cidrs
      security_groups = ingress.value.security_group_ids
    }
  }
}

resource "aws_db_parameter_group" "this" {
  name   = var.name
  family = var.engines[var.config.engine].family

  parameter {
    name  = local.engine.tls_parameter
    value = var.config.force_ssl ? local.engine.tls_on : local.engine.tls_off
  }
}

# Created up front so terraform destroy removes them with the instance.
resource "aws_cloudwatch_log_group" "this" {
  for_each          = toset(local.log_exports)
  name              = "/aws/rds/instance/${var.name}/${each.value}"
  retention_in_days = 7
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  count              = local.create_role ? 1 : 0
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "this" {
  count = local.create_role ? 1 : 0
  name  = "permissions"
  role  = aws_iam_role.this[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      for statement in var.config.associated_role.statements : {
        Effect   = "Allow"
        Action   = statement.actions
        Resource = statement.resources
      }
    ]
  })
}

# A static master password for databases that don't use Secrets Manager. It is ephemeral and
# write-only, so it never lands in Terraform state, and nobody ever learns it.
ephemeral "aws_secretsmanager_random_password" "master" {
  count               = var.config.managed_password ? 0 : 1
  password_length     = 32
  exclude_punctuation = true
}

# By default the master password lives in Secrets Manager.
resource "aws_db_instance" "this" {
  identifier                          = var.name
  engine                              = var.config.engine
  engine_version                      = var.engines[var.config.engine].version
  engine_lifecycle_support            = "open-source-rds-extended-support-disabled"
  instance_class                      = var.instance_class
  allocated_storage                   = 20
  storage_type                        = "gp3"
  storage_encrypted                   = var.config.encrypted
  kms_key_id                          = var.config.encrypted ? var.kms_key_arn : null
  username                            = "dbadmin"
  manage_master_user_password         = var.config.managed_password ? true : null
  password_wo                         = var.config.managed_password ? null : ephemeral.aws_secretsmanager_random_password.master[0].random_password
  password_wo_version                 = var.config.managed_password ? null : 1
  iam_database_authentication_enabled = var.config.iam_auth
  db_subnet_group_name                = var.config.public ? var.public_subnet_group : var.private_subnet_group
  publicly_accessible                 = var.config.public
  vpc_security_group_ids              = [aws_security_group.this.id]
  parameter_group_name                = aws_db_parameter_group.this.name
  backup_retention_period             = var.config.backup_retention
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true
  enabled_cloudwatch_logs_exports     = local.log_exports
  deletion_protection                 = false
  skip_final_snapshot                 = true
  delete_automated_backups            = true
  apply_immediately                   = true
  depends_on                          = [aws_cloudwatch_log_group.this]
}

resource "aws_db_instance_role_association" "this" {
  count                  = local.create_role ? 1 : 0
  db_instance_identifier = aws_db_instance.this.identifier
  feature_name           = var.config.associated_role.feature
  role_arn               = aws_iam_role.this[0].arn
  depends_on             = [aws_iam_role_policy.this]
}

# A manual snapshot; "all" in shared_accounts makes it public, which RDS only allows when unencrypted.
resource "aws_db_snapshot" "this" {
  count                  = var.config.snapshot == null ? 0 : 1
  db_instance_identifier = aws_db_instance.this.identifier
  db_snapshot_identifier = "${var.name}-${var.config.snapshot.name}"
  shared_accounts        = var.config.snapshot.shared_accounts
}
