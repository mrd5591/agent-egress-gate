# Two roles, because they are used at different times by different principals.
# The execution role belongs to the ECS agent pulling the image and shipping
# logs; the task role belongs to the process inside the container. Collapsing
# them into one is the most common way a container ends up able to do things
# its code never needed.

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = var.tags
}

# Log writes are scoped to the log group this module creates. The AWS managed
# execution policy grants logs:* on "*", which is broader than this task ever
# needs, so it is written out rather than attached.
data "aws_iam_policy_document" "execution" {
  statement {
    sid    = "PullImage"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"] # GetAuthorizationToken has no resource to scope to.
  }

  statement {
    sid    = "PullThisImageOnly"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = [aws_ecr_repository.gate.arn]
  }

  statement {
    sid    = "WriteToThisLogGroupOnly"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.gate.arn}:*"]
  }

  statement {
    sid       = "ReadThePolicyParameterOnly"
    effect    = "Allow"
    actions   = ["ssm:GetParameters"]
    resources = [var.policy_parameter_arn]
  }
}

resource "aws_iam_role_policy" "execution" {
  name_prefix = "${var.name}-exec-"
  role        = aws_iam_role.execution.id
  policy      = data.aws_iam_policy_document.execution.json
}

# The gate process itself calls no AWS API. The task role exists so the task
# has an identity for logging and network attribution, and it grants nothing.
# If a future version reads the policy from S3, that permission goes here.
resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = var.tags
}
