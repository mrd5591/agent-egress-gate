locals {
  container_name = "${var.name}-gate"
}

resource "aws_ecr_repository" "gate" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  tags                 = var.tags

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_cloudwatch_log_group" "gate" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
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
      # entrypoint writes it to a file before starting. Keeping the policy out
      # of the image means changing it does not mean rebuilding.
      secrets = [
        {
          name      = "EGRESSGATE_POLICY"
          valueFrom = var.policy_parameter_arn
        },
      ]

      command = [
        "sh", "-c",
        join(" ", [
          "printf '%s' \"$EGRESSGATE_POLICY\" > /tmp/policy.yaml &&",
          "exec /usr/local/bin/egressgate serve",
          "--policy /tmp/policy.yaml",
          "--listen 0.0.0.0:${var.proxy_port}",
          "--admin 0.0.0.0:${var.admin_port}",
        ])
      ]

      portMappings = [
        {
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

      readonlyRootFilesystem = false # the entrypoint writes /tmp/policy.yaml
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
}

data "aws_region" "current" {}
