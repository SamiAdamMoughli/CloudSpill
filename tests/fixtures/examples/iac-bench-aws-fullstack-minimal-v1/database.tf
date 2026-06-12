# Managed data tier

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnets"
  subnet_ids = aws_subnet.private_db[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnets"
  }
}

resource "aws_db_parameter_group" "postgres" {
  name   = "${local.name_prefix}-postgres-pg"
  family = "postgres15"

  parameter {
    name  = "log_statement"
    value = "ddl"
  }
}

resource "aws_db_instance" "primary" {
  identifier = "${local.name_prefix}-postgres"

  engine         = "postgres"
  engine_version = "15.7"
  instance_class = "db.t3.medium"

  allocated_storage          = 50
  storage_type               = "gp3"
  storage_encrypted          = false
  multi_az                   = true
  publicly_accessible        = true
  auto_minor_version_upgrade = true

  db_name                     = "appdb"
  username                    = var.db_master_username
  manage_master_user_password = true

  db_subnet_group_name  = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name  = aws_db_parameter_group.postgres.name

  backup_retention_period = 7
  deletion_protection     = true
  skip_final_snapshot     = true

  tags = {
    Name = "${local.name_prefix}-postgres"
  }
}