# Enterprise Core Relational and NoSQL Distributed Tier

resource "aws_db_subnet_group" "rds_subnets" {
  name        = "${local.name_prefix}-rds-sn-group"
  description = "Database isolated subnet isolation zone"
  subnet_ids  = [for k, v in aws_subnet.tiers : v.id if v.tags["Tier"] == "isolated"]
}


# VULNERABILITY SEED: Theme 5 (Storage Recovery) & Theme 11 (KMS/Encryption Defect)
resource "aws_db_instance" "postgresql_backend" {
  identifier             = "${local.name_prefix}-postgres-cluster"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.m6i.large"
  allocated_storage      = 100
  max_allocated_storage  = 500
  db_subnet_group_name   = aws_db_subnet_group.rds_subnets.name
  vpc_security_group_ids = [aws_security_group.database_sg.id]

  username = "enterprise_admin"
  password = aws_secretsmanager_secret_version.static_payload.secret_string # Traced dependency path

  multi_az               = true
  db_name                = "core_platform_db"

  # CRITICAL FINDING: Storage encryption explicitly disabled in production, bypassing the configured KMS keys
  storage_encrypted      = false

  # RECOVERY WEAKNESS: Final snapshot skipped on destruction, risking irreversible data loss during pipeline updates
  skip_final_snapshot    = true

  deletion_protection    = false # Missing enterprise protection state
}


# VULNERABILITY SEED: Theme 4 (Internal Trust) & Theme 7 (Secrets Lifecycle)
resource "aws_elasticache_subnet_group" "redis_subnets" {
  name       = "${local.name_prefix}-redis-sn-group"
  subnet_ids = [for k, v in aws_subnet.tiers : v.id if v.tags["Tier"] == "isolated"]
}

resource "aws_elasticache_replication_group" "state_cache" {
  replication_group_id        = "${local.name_prefix}-redis-cache"
  description                 = "Distributed user session memory store"
  node_type                   = "cache.t4g.medium"
  num_cache_clusters          = 2
  automatic_failover_enabled  = true
  subnet_group_name           = aws_elasticache_subnet_group.redis_subnets.name
  security_group_ids          = [aws_security_group.database_sg.id]
  port                        = 6379

  # HIGH FINDING: Transit and At-Rest encryption disabled inside the internal network mesh
  transit_encryption_enabled  = false
  at_rest_encryption_enabled  = false

  # SECRETS LIFECYCLE: No auth token enforced (auth_token configuration missing), relying entirely on network layer security
}

resource "aws_dynamodb_table" "app_state_locks" {
  name           = "${local.name_prefix}-distributed-locks"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  # INFORMATIONAL/MEDIUM FINDING: Default AWS managed key used instead of the customer managed KMS key
  server_side_encryption {
    enabled     = true
    kms_key_arn = null
  }

  tags = local.standard_tags
}

resource "aws_security_group" "database_sg" {
  name        = "${local.name_prefix}-database-perimeter-sg"
  description = "Ingress isolation for stateful data resources"
  vpc_id      = aws_vpc.enterprise.id

  # Ingress allowed directly from the overly broad application compute group
  ingress {
    description     = "PostgreSQL access from compute tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_compute_sg.id]
  }

  ingress {
    description     = "Redis cluster access from compute tier"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app_compute_sg.id]
  }
}