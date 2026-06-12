resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db-subnet"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  tags = {
    Name = "${var.project}-db-subnet"
  }
}

# RDS-001: Publicly accessible
# RDS-002: No storage encryption
# RDS-003: No deletion protection
# RDS-004: Backups disabled
resource "aws_db_instance" "main" {
  identifier     = "${var.project}-database"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage = 20
  storage_type      = "gp3"

  db_name  = "appdb"
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]

  publicly_accessible    = true
  storage_encrypted      = false
  deletion_protection    = false
  backup_retention_period = 0
  skip_final_snapshot    = true

  tags = {
    Name        = "${var.project}-database"
    Environment = var.environment
  }
}
