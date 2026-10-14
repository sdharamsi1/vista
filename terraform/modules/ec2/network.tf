# Every instance type a scenario uses; AZs must offer all of them (some us-east-1 AZs lack Graviton).
locals {
  instance_types = ["t4g.nano", "t4g.micro", "t4g.small"]
  offered        = data.aws_ec2_instance_type_offerings.available
  # AZs that offer every type, in a stable order; the load balancer needs two.
  complete_azs = sort([
    for az in distinct(local.offered.locations) : az
    if length([for location in local.offered.locations : location if location == az]) == length(local.instance_types)
  ])
  availability_zones = slice(local.complete_azs, 0, 2)
}

data "aws_ec2_instance_type_offerings" "available" {
  location_type = "availability-zone"
  filter {
    name   = "instance-type"
    values = local.instance_types
  }
}

# ---------- Production VPC: public, ops, and private (NAT) subnets ----------

resource "aws_vpc" "prod" {
  tags                 = { Name = "${var.name}-prod" }
  cidr_block           = var.prod_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "prod" {
  tags   = { Name = "${var.name}-prod" }
  vpc_id = aws_vpc.prod.id
}

# Load balancer and NAT gateway subnets, plus the marketing site.
resource "aws_subnet" "public" {
  count             = length(local.availability_zones)
  tags              = { Name = "${var.name}-prod-public-${count.index}" }
  vpc_id            = aws_vpc.prod.id
  cidr_block        = cidrsubnet(var.prod_cidr, 8, count.index)
  availability_zone = local.availability_zones[count.index]
}

# Operations subnet: Internet-routed, with its own network ACL.
resource "aws_subnet" "ops" {
  tags              = { Name = "${var.name}-prod-ops" }
  vpc_id            = aws_vpc.prod.id
  cidr_block        = cidrsubnet(var.prod_cidr, 8, 5)
  availability_zone = local.availability_zones[0]
}

# Application subnets: outbound through NAT only.
resource "aws_subnet" "private" {
  count             = length(local.availability_zones)
  tags              = { Name = "${var.name}-prod-private-${count.index}" }
  vpc_id            = aws_vpc.prod.id
  cidr_block        = cidrsubnet(var.prod_cidr, 8, 10 + count.index)
  availability_zone = local.availability_zones[count.index]
}

resource "aws_route_table" "public" {
  tags   = { Name = "${var.name}-prod-public" }
  vpc_id = aws_vpc.prod.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.prod.id
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "ops" {
  subnet_id      = aws_subnet.ops.id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  tags   = { Name = "${var.name}-prod-nat" }
  domain = "vpc"
}

resource "aws_nat_gateway" "prod" {
  tags          = { Name = "${var.name}-prod" }
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.prod]
}

resource "aws_route_table" "private" {
  tags   = { Name = "${var.name}-prod-private" }
  vpc_id = aws_vpc.prod.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.prod.id
  }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# The network team blocks the Prometheus exporter port at the subnet edge, whatever the security
# groups allow. Network ACLs are stateless, so everything else, including return traffic, is allowed.
resource "aws_network_acl" "ops" {
  tags       = { Name = "${var.name}-prod-ops" }
  vpc_id     = aws_vpc.prod.id
  subnet_ids = [aws_subnet.ops.id]

  ingress {
    rule_no    = 90
    action     = "deny"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 9100
    to_port    = 9100
  }
  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

# ---------- Legacy VPC: one Internet-routed subnet with the default network ACL ----------

resource "aws_vpc" "legacy" {
  tags                 = { Name = "${var.name}-legacy" }
  cidr_block           = var.legacy_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "legacy" {
  tags   = { Name = "${var.name}-legacy" }
  vpc_id = aws_vpc.legacy.id
}

resource "aws_subnet" "legacy" {
  tags              = { Name = "${var.name}-legacy-public" }
  vpc_id            = aws_vpc.legacy.id
  cidr_block        = cidrsubnet(var.legacy_cidr, 8, 0)
  availability_zone = local.availability_zones[0]
}

resource "aws_route_table" "legacy" {
  tags   = { Name = "${var.name}-legacy-public" }
  vpc_id = aws_vpc.legacy.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.legacy.id
  }
}

resource "aws_route_table_association" "legacy" {
  subnet_id      = aws_subnet.legacy.id
  route_table_id = aws_route_table.legacy.id
}

# Where a scenario's config.subnet places it, and whether it gets a public IP there.
locals {
  subnets = {
    public    = { id = aws_subnet.public[0].id, vpc_id = aws_vpc.prod.id, public_ip = true }
    ops       = { id = aws_subnet.ops.id, vpc_id = aws_vpc.prod.id, public_ip = true }
    private   = { id = aws_subnet.private[0].id, vpc_id = aws_vpc.prod.id, public_ip = false }
    private_b = { id = aws_subnet.private[1].id, vpc_id = aws_vpc.prod.id, public_ip = false }
    legacy    = { id = aws_subnet.legacy.id, vpc_id = aws_vpc.legacy.id, public_ip = true }
  }
}
