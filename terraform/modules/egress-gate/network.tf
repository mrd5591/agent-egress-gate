# This file is the security argument of the whole repository.
#
# The proxy decides which hosts an agent may reach. These rules decide that
# the proxy is the only thing an agent can reach at all. Without the agent
# egress rule below, the gate is advice; with it, the gate is the only route
# off the subnet, and an agent that ignores its HTTP_PROXY setting simply
# fails to connect rather than quietly bypassing the policy.

resource "aws_security_group" "gate" {
  name_prefix = "${var.name}-gate-"
  description = "Egress gate: accepts proxy traffic from agents and reaches the internet"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-gate" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "agent" {
  name_prefix = "${var.name}-agent-"
  description = "Agent tasks: may reach the egress gate and nothing else"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-agent" })

  lifecycle {
    create_before_destroy = true
  }
}

# The gate accepts proxy traffic only from tasks carrying the agent group.
resource "aws_vpc_security_group_ingress_rule" "gate_from_agents" {
  security_group_id            = aws_security_group.gate.id
  referenced_security_group_id = aws_security_group.agent.id
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  ip_protocol                  = "tcp"
  description                  = "Proxy traffic from agent tasks"
  tags                         = var.tags
}

# The admin plane is reachable only from the groups explicitly named, and by
# default from nothing at all. It is deliberately not open to the agent group:
# an agent that could POST /reload could replace the policy constraining it.
resource "aws_vpc_security_group_ingress_rule" "gate_admin" {
  for_each = toset(var.admin_ingress_security_group_ids)

  security_group_id            = aws_security_group.gate.id
  referenced_security_group_id = each.value
  from_port                    = var.admin_port
  to_port                      = var.admin_port
  ip_protocol                  = "tcp"
  description                  = "Metrics scrape and policy reload"
  tags                         = var.tags
}

# The gate itself needs the internet. This is the only egress to 0.0.0.0/0 in
# the module, and it belongs to the component whose entire job is deciding
# what may traverse it.
#
# The ports come from a variable because a policy rule may name any port. When
# these were hardcoded to 80 and 443, a rule naming anything else was accepted
# by the policy parser, evaluated as allow, and audited as allow - and then
# died as an unexplained upstream timeout, with nothing in the evidence log
# saying the network had refused what the gate permitted.
#
# Terraform cannot check the two agree: the policy lives in an SSM parameter
# (var.policy_parameter_arn) whose contents this module never reads, by design.
# So the module cannot validate the pair, and the README says plainly that
# widening a policy's ports means widening this variable too. That is a
# documented operator obligation, not a closed loop - said here rather than
# left for someone to discover from a timeout.
resource "aws_vpc_security_group_egress_rule" "gate_to_internet" {
  for_each = toset([for p in var.upstream_ports : tostring(p)])

  security_group_id = aws_security_group.gate.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  ip_protocol       = "tcp"
  description       = "Upstream port ${each.value}, filtered by policy inside the gate"
  tags              = var.tags
}

# The two rules above replaced a pair of individually named ones. Without these
# blocks, upgrading the module would destroy the gate's only egress and
# recreate it, which for the duration of the apply is an outage of the thing
# every agent routes through.
moved {
  from = aws_vpc_security_group_egress_rule.gate_to_internet_https
  to   = aws_vpc_security_group_egress_rule.gate_to_internet["443"]
}

moved {
  from = aws_vpc_security_group_egress_rule.gate_to_internet_http
  to   = aws_vpc_security_group_egress_rule.gate_to_internet["80"]
}

# The agent's only route to anything outside the VPC.
resource "aws_vpc_security_group_egress_rule" "agent_to_gate_only" {
  security_group_id            = aws_security_group.agent.id
  referenced_security_group_id = aws_security_group.gate.id
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  ip_protocol                  = "tcp"
  description                  = "The agent's only route out of the VPC"
  tags                         = var.tags
}

# Fargate platform version 1.4.0 moved the image pull and the ECS agent's own
# calls onto the task ENI, so they are subject to the task's security group. A
# task whose only egress rule is the one above cannot pull its image and never
# starts.
#
# The fix is not to open the internet: it is to let the task reach the VPC
# endpoints for ECR, CloudWatch Logs and S3, which stay inside the VPC.
# Arbitrary egress still has exactly one route, through the gate.
#
# Both variables default to empty, so a caller who has not created endpoints
# gets the strict configuration and the README's caveat explains why the task
# will not start without them.
resource "aws_vpc_security_group_egress_rule" "agent_to_vpc_endpoints" {
  for_each = toset(var.vpc_endpoint_security_group_ids)

  security_group_id            = aws_security_group.agent.id
  referenced_security_group_id = each.value
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Interface endpoints for ECR and CloudWatch Logs, so the task can start"
  tags                         = var.tags
}

# S3 is reached through a gateway endpoint, which is addressed by prefix list
# rather than by security group. ECR image layers live in S3.
resource "aws_vpc_security_group_egress_rule" "agent_to_s3_gateway" {
  count = var.s3_gateway_prefix_list_id == null ? 0 : 1

  security_group_id = aws_security_group.agent.id
  prefix_list_id    = var.s3_gateway_prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "S3 gateway endpoint, where ECR image layers are stored"
  tags              = var.tags
}

# The gate resolves upstream hostnames through the VPC resolver at VPC+2.
# Security groups do not filter traffic to the Route 53 Resolver, which is why
# no DNS egress rule appears here. That stops being true if the VPC uses a
# custom DHCP options set pointing at a private forwarder, in which case this
# module needs an egress rule for it.
