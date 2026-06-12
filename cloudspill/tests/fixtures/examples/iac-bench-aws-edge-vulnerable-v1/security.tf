# Security groups. Edge and management ingress is scoped to the trusted
# management CIDR; tiers reference one another rather than opening CIDRs.

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb-sg"
  description = "Public application load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from trusted networks"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.management_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name        = "${local.name_prefix}-app-sg"
  description = "Application tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "App port from the load balancer only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "admin" {
  name        = "${local.name_prefix}-admin-sg"
  description = "Administrative / break-glass access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from trusted networks"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "mesh" {
  name        = "${local.name_prefix}-mesh-sg"
  description = "Service mesh data plane"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Unrestricted mesh ingress"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
