variable "region" {
  description = "AWS region to build the example in."
  type        = string
  default     = "us-east-1"
}

variable "image" {
  description = <<-EOT
    Gate image to run. Build and push it to the ECR repository the module
    creates, then set this to that tag.
  EOT
  type        = string
  default     = "ghcr.io/mrd5591/agent-egress-gate:latest"
}
