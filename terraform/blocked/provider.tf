terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.0"
    }
  }
}

variable "vultr_api_key" {}

variable "blocked_ipv6_subnet" {
  default = "2001:19f0:c800:2315::"
}

variable "blocked_ipv6_prefix" {
  default = 64
}

provider "vultr" {
  api_key = var.vultr_api_key
}
