# A worked example: a VPC whose private subnets reach the internet only
# through a NAT gateway, an SSM parameter holding the policy, and the gate.
#
# It exists so that `terraform validate` runs against a real caller rather
# than the module in isolation, and so a reader can see what wiring the module
# actually expects.

terraform {
  required_version = "~> 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name     = "agent-egress-example"
  azs      = slice(data.aws_availability_zones.available.names, 0, 2)
  vpc_cidr = "10.42.0.0/16"

  tags = {
    Project = "agent-egress-gate"
    Example = "true"
  }
}

resource "aws_vpc" "this" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = local.name })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

# One public subnet, holding the NAT gateway. Nothing else runs here.
resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(local.vpc_cidr, 8, 0)
  availability_zone = local.azs[0]
  tags              = merge(local.tags, { Name = "${local.name}-public" })
}

resource "aws_subnet" "private" {
  count = length(local.azs)

  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(local.vpc_cidr, 8, count.index + 10)
  availability_zone = local.azs[count.index]
  tags              = merge(local.tags, { Name = "${local.name}-private-${count.index}" })
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = local.tags
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  tags          = local.tags

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this.id
  }
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# The policy lives in SSM so it can be changed without rebuilding the image.
resource "aws_ssm_parameter" "policy" {
  name  = "/${local.name}/policy"
  type  = "SecureString"
  tags  = local.tags
  value = file("${path.module}/policy.yaml")
}

# An agent task can only reach the gate, so it cannot pull its own image from
# the internet. These endpoints keep that traffic inside the VPC. Without them
# the strict security group is correct and the agent never starts.
resource "aws_security_group" "endpoints" {
  name_prefix = "${local.name}-endpoints-"
  description = "Interface VPC endpoints for ECR and CloudWatch Logs"
  vpc_id      = aws_vpc.this.id
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_vpc" {
  security_group_id = aws_security_group.endpoints.id
  cidr_ipv4         = local.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from inside the VPC"
  tags              = local.tags
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(["ecr.api", "ecr.dkr", "logs"])

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "${local.name}-${each.value}" })
}

# ECR image layers live in S3, which is reached through a gateway endpoint.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  tags              = merge(local.tags, { Name = "${local.name}-s3" })
}

# Service Connect gives the gate a stable name, so agents have something to
# put in HTTP_PROXY.
resource "aws_service_discovery_http_namespace" "this" {
  name        = local.name
  description = "Service Connect namespace for the egress gate"
  tags        = local.tags
}

module "egress_gate" {
  source = "../modules/egress-gate"

  name                 = local.name
  vpc_id               = aws_vpc.this.id
  private_subnet_ids   = aws_subnet.private[*].id
  policy_parameter_arn = aws_ssm_parameter.policy.arn
  image                = var.image
  tags                 = local.tags

  vpc_endpoint_security_group_ids = [aws_security_group.endpoints.id]
  s3_gateway_prefix_list_id       = aws_vpc_endpoint.s3.prefix_list_id

  enable_service_connect        = true
  service_connect_namespace_arn = aws_service_discovery_http_namespace.this.arn

  # So `terraform destroy` on an example people are meant to try does not
  # fail on a repository that still holds an image.
  ecr_force_delete = true
}
