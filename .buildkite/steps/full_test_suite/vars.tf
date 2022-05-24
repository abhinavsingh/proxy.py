// AWS specific
variable "aws_subnet" {
  type    = string
  default = "default"
}

variable "allow_list" {
  type = list(string)
}

variable "solana_instance_type" {
  type = string
}

variable "proxy_instance_type" {
  type = string
}

variable "ami" {
  type = string
}

// software sprcific
variable "branch" {
  type = string
}


variable "proxy_model_commit" {
  type = string
}


variable "neon_evm_commit" {
  type = string
}


variable "faucet_model_commit" {
  type = string
}
