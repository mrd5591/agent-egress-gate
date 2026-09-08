terraform {
  required_version = "~> 1.9"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Pinned to a major version. An unpinned provider is a module that
      # builds today and fails in six months for reasons nobody recorded.
      version = "~> 5.60"
    }
  }
}
