# Current default versions of each engine the scenarios use.
data "aws_rds_engine_version" "this" {
  engine       = "postgres"
  default_only = true
  latest       = true
}

data "aws_rds_engine_version" "mysql" {
  engine       = "mysql"
  default_only = true
  latest       = true
}

# Pick two AZs that offer the instance class (a DB subnet group needs at least two).
data "aws_rds_orderable_db_instance" "this" {
  engine         = "postgres"
  engine_version = data.aws_rds_engine_version.this.version
  instance_class = var.instance_class
  license_model  = "postgresql-license"
  storage_type   = "gp3"
}
locals {
  availability_zones = slice(sort(data.aws_rds_orderable_db_instance.this.availability_zones), 0, 2)
}
resource "aws_vpc" "this" {
  tags                 = { Name = "${var.name}-data" }
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_internet_gateway" "this" {
  tags   = { Name = "${var.name}-data" }
  vpc_id = aws_vpc.this.id
}
resource "aws_subnet" "public" {
  count             = length(local.availability_zones)
  tags              = { Name = "${var.name}-data-public-${count.index}" }
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.cidr_block, 8, count.index)
  availability_zone = local.availability_zones[count.index]
}
resource "aws_subnet" "private" {
  count             = length(local.availability_zones)
  tags              = { Name = "${var.name}-data-private-${count.index}" }
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.cidr_block, 8, 10 + count.index)
  availability_zone = local.availability_zones[count.index]
}
resource "aws_route_table" "public" {
  tags   = { Name = "${var.name}-data-public" }
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
}
resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}
# Only the local VPC route: no Internet gateway and no NAT.
resource "aws_route_table" "private" {
  tags   = { Name = "${var.name}-data-private" }
  vpc_id = aws_vpc.this.id
}
resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
# Subnets in the public group route to the Internet gateway; subnets in the private group do not.
resource "aws_db_subnet_group" "public" {
  name       = "${var.name}-db-public"
  subnet_ids = aws_subnet.public[*].id
}
resource "aws_db_subnet_group" "private" {
  name       = "${var.name}-db-private"
  subnet_ids = aws_subnet.private[*].id
}
