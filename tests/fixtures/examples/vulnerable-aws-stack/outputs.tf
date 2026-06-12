output "web_server_public_ip" {
  description = "Public IP of the web server"
  value       = aws_instance.web.public_ip
}

output "database_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
}

output "upload_bucket" {
  description = "S3 bucket for user uploads"
  value       = aws_s3_bucket.user_uploads.bucket
}

output "lambda_function_name" {
  description = "Data processor Lambda function name"
  value       = aws_lambda_function.data_processor.function_name
}
