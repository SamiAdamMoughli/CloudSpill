variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "iac-bench-aws-multitier-mixed"
}

variable "environment" {
  type    = string
  default = "v1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.60.0.0/16"
}

variable "public_subnet_cidrs" {
  type = list(string)
  default = ["10.60.0.0/24", "10.60.1.0/24"]
}

variable "private_app_subnet_cidrs" {
  type = list(string)
  default = ["10.60.10.0/24", "10.60.11.0/24"]
}

variable "private_db_subnet_cidrs" {
  type = list(string)
  default = ["10.60.20.0/24", "10.60.21.0/24"]
}

variable "db_master_username" {
  type    = string
  default = "appadmin"
}

variable "allowed_ssh_cidr" {
  type    = string
  default = "0.0.0.0/0"
}