# rds-07: RDS Proxy in front of the orders database (rds-06), with debug logging on and TLS between
# clients and the proxy optional (require_tls false). The proxy authenticates to the database with
# the instance's managed secret.

resource "aws_security_group" "proxy" {
  count       = local.proxy_enabled ? 1 : 0
  tags        = { Name = "${var.name}-orders-db-proxy" }
  name        = "${var.name}-orders-db-proxy"
  description = "Orders database proxy"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "App tier"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block]
  }
  egress {
    description = "Orders database"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block]
  }
}

data "aws_iam_policy_document" "proxy_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "proxy" {
  count              = local.proxy_enabled ? 1 : 0
  name               = "${var.name}-orders-db-proxy"
  assume_role_policy = data.aws_iam_policy_document.proxy_assume.json
}

resource "aws_iam_role_policy" "proxy" {
  count = local.proxy_enabled ? 1 : 0
  name  = "read-db-secret"
  role  = aws_iam_role.proxy[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = module.scenario[local.proxy_target].master_secret_arn
    }]
  })
}

resource "aws_db_proxy" "orders" {
  count                  = local.proxy_enabled ? 1 : 0
  name                   = "${var.name}-${local.all_scenarios["rds-07"].name}"
  engine_family          = "POSTGRESQL"
  role_arn               = aws_iam_role.proxy[0].arn
  vpc_subnet_ids         = aws_subnet.private[*].id
  vpc_security_group_ids = [aws_security_group.proxy[0].id]
  require_tls            = false
  debug_logging          = true
  idle_client_timeout    = 1800

  auth {
    auth_scheme               = "SECRETS"
    secret_arn                = module.scenario[local.proxy_target].master_secret_arn
    iam_auth                  = "DISABLED"
    client_password_auth_type = "POSTGRES_SCRAM_SHA_256"
  }

  depends_on = [aws_iam_role_policy.proxy]
}

resource "aws_db_proxy_default_target_group" "orders" {
  count         = local.proxy_enabled ? 1 : 0
  db_proxy_name = aws_db_proxy.orders[0].name

  connection_pool_config {
    max_connections_percent = 90
  }
}

resource "aws_db_proxy_target" "orders" {
  count                  = local.proxy_enabled ? 1 : 0
  db_proxy_name          = aws_db_proxy.orders[0].name
  target_group_name      = aws_db_proxy_default_target_group.orders[0].name
  db_instance_identifier = module.scenario[local.proxy_target].instance_identifier
}

# Null when the proxy is off; only the orders database references it.
locals {
  proxy_security_group_id = one(aws_security_group.proxy[*].id)
}
