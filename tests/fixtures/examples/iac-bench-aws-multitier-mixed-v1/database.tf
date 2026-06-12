# Managed state and cache tier

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnets"
  subnet_ids = aws_subnet.private_db[*].id
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

  allocated_storage          = 100
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
}

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name_prefix}-redis-subnets"
  subnet_ids = aws_subnet.private_app[*].id
}

resource "aws_elasticache_parameter_group" "redis" {
  name   = "${local.name_prefix}-redis-pg"
  family = "redis7"
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${replace(local.name_prefix, "_", "-")}-redis"
  description                = "Cache tier for platform"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = "cache.t3.micro"
  port                       = 6379
  parameter_group_name       = aws_elasticache_parameter_group.redis.name
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [aws_security_group.cache.id]
  num_node_groups            = 1
  replicas_per_node_group    = 1
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = false
  transit_encryption_enabled = false
  apply_immediately          = true
}
