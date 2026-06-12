output "vpc_id" {
  value = aws_vpc.main.id
}

output "alb_dns_name" {
  value = aws_lb.app.dns_name
}

output "rds_endpoint" {
  value = aws_db_instance.primary.endpoint
}

output "lambda_name" {
  value = aws_lambda_function.utility.function_name
}