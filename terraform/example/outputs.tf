output "agent_security_group_id" {
  description = "Attach this to agent tasks so the gate is their only way out."
  value       = module.egress_gate.agent_security_group_id
}

output "ecr_repository_url" {
  description = "Push the gate image here before the service can start."
  value       = module.egress_gate.ecr_repository_url
}

output "proxy_endpoint_hint" {
  description = "Set HTTP_PROXY and HTTPS_PROXY on the agent to the gate's task address on this port."
  value       = "http://<gate-task-ip>:${module.egress_gate.proxy_port}"
}

output "log_group_name" {
  description = "Where the audit log lands."
  value       = module.egress_gate.log_group_name
}
