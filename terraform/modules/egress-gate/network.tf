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
resource "aws_vpc_security_group_egress_rule" "gate_to_internet_https" {
  security_group_id = aws_security_group.gate.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Upstream HTTPS, filtered by policy inside the gate"
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "gate_to_internet_http" {
  security_group_id = aws_security_group.gate.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "Upstream HTTP, filtered by policy inside the gate"
  tags              = var.tags
}

# The one and only outbound rule an agent task gets.
resource "aws_vpc_security_group_egress_rule" "agent_to_gate_only" {
  security_group_id            = aws_security_group.agent.id
  referenced_security_group_id = aws_security_group.gate.id
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  ip_protocol                  = "tcp"
  description                  = "The only outbound rule an agent task has"
  tags                         = var.tags
}
