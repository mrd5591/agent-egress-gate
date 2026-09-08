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

variable "vpc_endpoint_security_group_ids" {
  description = <<-EOT
    Security groups of the interface VPC endpoints for ECR (api and dkr) and
    CloudWatch Logs. Agent tasks are given egress to these on 443 so they can
    pull their image and ship logs without reaching the internet.

    Leaving this empty produces the strictest configuration, in which an agent
    task on Fargate platform 1.4.0 or later cannot pull its image and will not
    start. See the README.
  EOT
  type        = list(string)
  default     = []
}

variable "s3_gateway_prefix_list_id" {
  description = <<-EOT
    Prefix list id of the S3 gateway endpoint, where ECR stores image layers.
    Null omits the rule, with the same consequence as an empty
    vpc_endpoint_security_group_ids.
  EOT
  type        = string
  default     = null
}

variable "enable_service_connect" {
  description = <<-EOT
    Register the gate in an ECS Service Connect namespace so agents can reach
    it by a stable DNS name instead of a task IP. Requires
    service_connect_namespace_arn.
  EOT
  type        = bool
  default     = false
}

variable "service_connect_namespace_arn" {
  description = "Cloud Map namespace ARN used when enable_service_connect is true."
  type        = string
  default     = null
}

variable "service_connect_dns_name" {
  description = "DNS name agents will use for the gate within the namespace."
  type        = string
  default     = "egress-gate"
}

variable "log_group_kms_key_arn" {
  description = <<-EOT
    KMS key for the CloudWatch log group that carries the audit log. Null uses
    the CloudWatch default encryption.
  EOT
  type        = string
  default     = null
}

variable "ecr_keep_images" {
  description = "How many images the ECR lifecycle policy retains."
  type        = number
  default     = 20

  validation {
    condition     = var.ecr_keep_images >= 1
    error_message = "At least one image must be retained."
  }
}

variable "ecr_force_delete" {
  description = <<-EOT
    Allow terraform destroy to remove the ECR repository even when it still
    holds images. Convenient for the example; leave false in production, where
    losing image history to a destroy is a bad trade.
  EOT
  type        = bool
  default     = false
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
  # Each task writes its own audit chain from sequence 1 into its own CloudWatch
  # stream, because the audit log goes to stdout and there is no file to resume
  # from. Two tasks therefore means two independently verifiable chains, not one
  # interleaved and unverifiable log. See "What the chain means on ECS" in the
  # README.
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
