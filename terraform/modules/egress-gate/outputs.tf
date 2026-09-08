output "agent_security_group_id" {
  description = <<-EOT
    Attach this to every agent task. It is the whole point of the module: a
    task carrying this group can reach the gate and nothing else.
  EOT
  value       = aws_security_group.agent.id
}

output "gate_security_group_id" {
  description = "Security group the gate tasks run with."
  value       = aws_security_group.gate.id
}

output "ecr_repository_url" {
  description = "Push the gate image here."
  value       = aws_ecr_repository.gate.repository_url
}

output "cluster_name" {
  description = "ECS cluster running the gate."
  value       = aws_ecs_cluster.gate.name
}

output "service_name" {
  description = "ECS service running the gate."
  value       = aws_ecs_service.gate.name
}

output "log_group_name" {
  description = "CloudWatch log group carrying the audit log."
  value       = aws_cloudwatch_log_group.gate.name
}

output "proxy_port" {
  description = "Port agents should send proxy traffic to."
  value       = var.proxy_port
}
