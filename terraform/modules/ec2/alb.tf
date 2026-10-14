# Internet-facing storefront load balancer (realistic tier only). HTTPS terminates here with a
# self-signed certificate imported into ACM; /api/* goes to the orders API, everything else to
# the storefront. Both targets sit in private subnets with no public IP.

resource "tls_private_key" "storefront" {
  count     = local.realistic ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "storefront" {
  count                 = local.realistic ? 1 : 0
  private_key_pem       = tls_private_key.storefront[0].private_key_pem
  validity_period_hours = 8760
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
  dns_names             = ["shop.${var.name}.example"]

  subject {
    common_name  = "shop.${var.name}.example"
    organization = var.name
  }
}

resource "aws_acm_certificate" "storefront" {
  count            = local.realistic ? 1 : 0
  private_key      = tls_private_key.storefront[0].private_key_pem
  certificate_body = tls_self_signed_cert.storefront[0].cert_pem
}

resource "aws_security_group" "alb" {
  count       = local.realistic ? 1 : 0
  tags        = { Name = "${var.name}-storefront-alb" }
  name        = "${var.name}-storefront-alb"
  description = "Public HTTPS for the storefront"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTP redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "App targets"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.prod_cidr]
  }
}

resource "aws_lb" "storefront" {
  count                      = local.realistic ? 1 : 0
  name                       = "${var.name}-storefront"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb[0].id]
  drop_invalid_header_fields = true
  enable_deletion_protection = false
}

resource "aws_lb_target_group" "storefront" {
  count    = local.realistic ? 1 : 0
  name     = "${var.name}-storefront"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.prod.id

  health_check {
    path    = "/"
    matcher = "200"
  }
}

resource "aws_lb_target_group" "orders" {
  count    = local.realistic ? 1 : 0
  name     = "${var.name}-orders-api"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.prod.id

  health_check {
    path    = "/api/"
    matcher = "200"
  }
}

resource "aws_lb_listener" "https" {
  count             = local.realistic ? 1 : 0
  load_balancer_arn = aws_lb.storefront[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.storefront[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.storefront[0].arn
  }
}

resource "aws_lb_listener_rule" "orders" {
  count        = local.realistic ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.orders[0].arn
  }

  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}

resource "aws_lb_listener" "http" {
  count             = local.realistic ? 1 : 0
  load_balancer_arn = aws_lb.storefront[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Null when the realistic tier is off; only realistic scenarios reference these.
locals {
  alb_security_group_id   = one(aws_security_group.alb[*].id)
  storefront_target_group = one(aws_lb_target_group.storefront[*].arn)
  orders_target_group     = one(aws_lb_target_group.orders[*].arn)
}
