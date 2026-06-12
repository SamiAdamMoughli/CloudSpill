output "vpc_id" {
  value = aws_vpc.main.id
}

output "data_bucket" {
  value = aws_s3_bucket.data.id
}

output "db_endpoint" {
  value = aws_db_instance.main.endpoint
}
