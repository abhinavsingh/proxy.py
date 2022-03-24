output "solana_ip" {
  value = aws_instance.solana.public_ip
}

output "proxy_ip" {
  value = aws_instance.proxy.public_ip
}

output "branch" {
  value = var.branch
}
