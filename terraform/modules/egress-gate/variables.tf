variable "name" {
  description = "Name prefix for every resource this module creates."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name))
    error_message = "The name must be lower-case alphanumeric with dashes, 2 to 31 characters, starting with a letter."
  }
}

variable "vpc_id" {
  description = "VPC the gate and the agents run in."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "The vpc_id must look like vpc-0123456789abcdef0."
  }
}

variable "private_subnet_ids" {
  description = <<-EOT
    Private subnets for the gate task. These must have a route to the internet
    through a NAT gateway; the gate is the only thing that needs one, which is
    the point.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) > 0
    error_message = "At least one private subnet is required."
  }
}

variable "proxy_port" {
  description = "Port the gate listens on for agent traffic."
  type        = number
  default     = 8080

  validation {
    condition     = var.proxy_port > 0 && var.proxy_port < 65536
    error_message = "The proxy_port must be between 1 and 65535."
  }
}

variable "admin_port" {
  description = <<-EOT
    Port for metrics, health and policy reload. This is never opened to the
    agent security group. Only the observability source in
    admin_ingress_security_group_ids can reach it.
  EOT
  type        = number
  default     = 9090

  validation {
    condition     = var.admin_port > 0 && var.admin_port < 65536
    error_message = "The admin_port must be between 1 and 65535."
  }
}

variable "admin_ingress_security_group_ids" {
  description = <<-EOT
    Security groups permitted to scrape the admin port, typically a Prometheus
    or agent collector. Empty means nothing can reach the admin plane, which
    is the safe default.
  EOT
  type        = list(string)
  default     = []
}

variable "policy_parameter_arn" {
  description = <<-EOT
    ARN of the SSM parameter holding the policy YAML. The task role is granted
    read on this one ARN and nothing else.
  EOT
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:ssm:", var.policy_parameter_arn))
    error_message = "The policy_parameter_arn must be an SSM parameter ARN."
  }
}

variable "image" {
  description = "Container image for the gate, including the tag or digest."
  type        = string
}

variable "task_cpu" {
  description = "Fargate CPU units for the gate task."
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "Fargate memory (MiB) for the gate task."
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of gate tasks. More than one needs a load balancer in front."
  type        = number
  default     = 2
}

variable "log_retention_days" {
  description = "CloudWatch log retention. Must be a value CloudWatch accepts."
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.log_retention_days
    )
    error_message = "The log_retention_days must be one of the values CloudWatch Logs accepts."
  }
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
