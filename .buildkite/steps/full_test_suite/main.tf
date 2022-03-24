terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    // Must be set from environment
  }
}

provider "aws" {
  region = "us-east-2"
}

data "aws_vpc" "default" {
  default = true
}

data "aws_key_pair" "ci-stands" {
  key_name = "ci-stands"
}

data "template_file" "solana_init" {
  template = file("solana_init.sh")

  vars = {
    branch = "${var.branch}"
  }
}

data "template_file" "proxy_init" {
  template = file("proxy_init.sh")

  vars = {
    branch             = "${var.branch}"
    proxy_model_commit = "${var.proxy_model_commit}"
    solana_ip          = aws_instance.solana.private_ip
    neon_evm_commit    = "${var.neon_evm_commit}"
  }
}

resource "random_id" "test-stand-solana" {
  byte_length = 4
  prefix      = "test-stand-solana-"
}

resource "aws_security_group" "test-stand-solana" {
  name        = random_id.test-stand-solana.hex
  description = "set of rules allow incoming traffic from ci test agents for OZ tests"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "allow incoming from ci test agent to SOLANA"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = var.allow_list
  }

  ingress {
    description = "allow incoming from world to SOLANA"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name    = "${var.branch}-test-stand-solana"
    purpose = "ci-oz-full-tests"
  }
}

resource "random_id" "test-stand-proxy" {
  byte_length = 4
  prefix      = "test-stand-proxy-"
}

resource "aws_security_group" "test-stand-proxy" {
  name        = random_id.test-stand-proxy.hex
  description = "set of rules allow incoming traffic from ci test agents for OZ tests"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "allow incoming from ci test agent to PROXY"
    from_port   = 9090
    to_port     = 9091
    protocol    = "tcp"
    cidr_blocks = var.allow_list
  }

  ingress {
    description = "allow incoming from ci test agent to FAUCET"
    from_port   = 3333
    to_port     = 3334
    protocol    = "tcp"
    cidr_blocks = var.allow_list
  }

  ingress {
    description = "allow incoming from world to PROXY"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name    = "${var.branch}-test-stand-proxy"
    purpose = "ci-oz-full-tests"
  }
}


resource "aws_instance" "solana" {
  instance_type          = var.solana_instance_type
  ami                    = var.ami
  key_name               = data.aws_key_pair.ci-stands.key_name
  vpc_security_group_ids = [aws_security_group.test-stand-solana.id]
  subnet_id              = var.aws_subnet

  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 50
  }

  user_data = data.template_file.solana_init.rendered

  tags = {
    Name    = "${var.branch}-test-stand-solana"
    purpose = "ci-oz-full-tests"
  }
}

resource "aws_instance" "proxy" {
  instance_type          = var.proxy_instance_type
  ami                    = var.ami
  key_name               = data.aws_key_pair.ci-stands.key_name
  vpc_security_group_ids = [aws_security_group.test-stand-proxy.id]
  subnet_id              = var.aws_subnet
  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 50
  }

  tags = {
    Name    = "${var.branch}-test-stand-proxy"
    purpose = "ci-oz-full-tests"
  }

  depends_on = [
    aws_instance.solana
  ]

  connection {
    type        = "ssh"
    user        = "ubuntu"
    host        = aws_instance.proxy.public_ip
    private_key = file("~/.ssh/ci-stands")
  }

  provisioner "file" {
    content     = data.template_file.proxy_init.rendered
    destination = "/tmp/proxy_init.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "echo '${aws_instance.solana.private_ip}' > /tmp/solana_host",
      "chmod a+x /tmp/proxy_init.sh",
      "sudo /tmp/proxy_init.sh"
    ]
  }
}


