locals {
  container_name = "${var.name}-gate"
  # Service Connect addresses a port by name, so the port mapping must carry
  # one.
  proxy_port_name = "proxy"
}

resource "aws_ecr_repository" "gate" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.ecr_force_delete
  tags                 = var.tags

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

# Immutable tags mean every build adds an image and none is ever replaced, so
# without this the repository grows without bound.
resource "aws_ecr_lifecycle_policy" "gate" {
  repository = aws_ecr_repository.gate.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the last ${var.ecr_keep_images} images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.ecr_keep_images
        }
        action = { type = "expire" }
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "gate" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  # The audit log lands here, and it is the evidence artefact. Encrypting the
  # group it lands in is cheap and on-message.
  kms_key_id = var.log_group_kms_key_arn
  tags       = var.tags

  # The name derives from var.name, so renaming the module instance would
  # otherwise destroy and recreate this group - silently deleting the evidence
  # the whole product is built around, as a side effect of a rename nobody
  # thought of as destructive.
  #
  # This is deliberately not governed by a variable: Terraform requires a
  # literal here and rejects any expression, including a var reference. Taking
  # the guard off is therefore an edit to this file, which is the point. To
  # remove the group on purpose, delete this block in its own commit, apply,
  # and put it back.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecs_cluster" "gate" {
  name = var.name
  tags = var.tags

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "gate" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  tags                     = var.tags

  container_definitions = jsonencode([
    {
      name      = local.container_name
      image     = var.image
      essential = true

      # The policy arrives as an environment variable read from SSM, and the
      # gate parses it directly. Keeping the policy out of the image means
      # changing it does not mean rebuilding.
      secrets = [
        {
          name      = "EGRESSGATE_POLICY"
          valueFrom = var.policy_parameter_arn
        },
      ]

      # These are arguments to the image's ENTRYPOINT, not a replacement for
      # it: ECS `command` maps to Docker's Cmd, which is appended to
      # Entrypoint rather than overriding it. An earlier version of this file
      # passed a shell invocation here, which produced
      # `egressgate sh -c ...` and exited immediately.
      #
      # Reading the policy from the environment is what removes the shell,
      # which in turn is what allows a read-only root filesystem below.
      command = [
        "serve",
        "--policy-env", "EGRESSGATE_POLICY",
        "--listen", "0.0.0.0:${var.proxy_port}",
        "--admin", "0.0.0.0:${var.admin_port}",
      ]

      portMappings = [
        {
          name          = local.proxy_port_name
          containerPort = var.proxy_port
          protocol      = "tcp"
        },
        {
          containerPort = var.admin_port
          protocol      = "tcp"
        },
      ]

      # The audit log goes to stdout and therefore to CloudWatch, which is the
      # one place the task itself cannot rewrite. A log the gate can edit is
      # not evidence.
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.gate.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "gate"
        }
      }

      # The gate writes nothing to disk: the policy comes from the
      # environment and the audit log goes to stdout.
      readonlyRootFilesystem = true
      user                   = "65532:65532"

      healthCheck = {
        command     = ["CMD-SHELL", "wget -q -O- http://127.0.0.1:${var.admin_port}/healthz || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
    },
  ])
}

resource "aws_ecs_service" "gate" {
  name                   = var.name
  cluster                = aws_ecs_cluster.gate.id
  task_definition        = aws_ecs_task_definition.gate.arn
  desired_count          = var.desired_count
  launch_type            = "FARGATE"
  enable_execute_command = false
  tags                   = var.tags

  # The task definition references the execution *role*, which gives Terraform
  # an implicit edge to that role but none to the inline policy attached to it.
  # Without this the service can start tasks before the policy exists: the
  # image pull or GetParameters then fails, the deployment circuit breaker
  # trips, and a correct configuration looks like a broken one.
  depends_on = [aws_iam_role_policy.execution]

  network_configuration {
    subnets = var.private_subnet_ids
    security_groups = [
      aws_security_group.gate.id,
    ]
    # The gate reaches the internet through the subnet's NAT gateway, not a
    # public IP. A public IP would make the gate itself reachable from
    # outside, which is the opposite of the point.
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Without this the gate has no stable address: awsvpc tasks get ephemeral
  # private IPs, and desired_count is above one. Service Connect gives agents
  # a name to put in HTTP_PROXY. DNS resolution is unaffected by the agent's
  # single egress rule, because security groups do not filter the VPC
  # resolver.
  dynamic "service_connect_configuration" {
    for_each = var.enable_service_connect ? [1] : []

    content {
      enabled   = true
      namespace = var.service_connect_namespace_arn

      service {
        port_name      = local.proxy_port_name
        discovery_name = var.service_connect_dns_name

        client_alias {
          port     = var.proxy_port
          dns_name = var.service_connect_dns_name
        }
      }
    }
  }
}

data "aws_region" "current" {}
