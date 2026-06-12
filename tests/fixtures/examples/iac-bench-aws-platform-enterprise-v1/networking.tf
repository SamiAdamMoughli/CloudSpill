# Multi-AZ Core Enterprise Network with Segmentation Drift
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "enterprise_vpc" {
  cidr_block           = "10.200.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = merge(local.tags, { Name = "${var.project_name}-vpc" })
}

# Subnets Layers: Public, Private, Isolated
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.enterprise_vpc.id
  cidr_block              = "10.200.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Tier = "Public" })
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.enterprise_vpc.id
  cidr_block        = "10.200.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge(local.tags, { Tier = "Private" })
}

resource "aws_subnet" "isolated" {
  count             = 2
  vpc_id            = aws_vpc.enterprise_vpc.id
  cidr_block        = "10.200.${count.index + 20}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge(local.tags, { Tier = "Isolated" })
}

# Public ALB Security Group
resource "aws_security_group" "alb_sg" {
  name        = "prd-public-alb-sg"
  description = "Ingress control for external application load balancer"
  vpc_id      = aws_vpc.enterprise_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
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

# VULNERABILITY SEED: Theme 6 (Network Segmentation Drift) & Theme 12 (Public Management)
resource "aws_security_group" "app_tier_sg" {
  name        = "prd-app-compute-sg"
  description = "Security group for ECS Enterprise tasks"
  vpc_id      = aws_vpc.enterprise_vpc.id

  ingress {
    description     = "Allow traffic from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Drift: App tier directly exposes an administrative port to the entire VPC and outside routes
  ingress {
    description = "Temporary debugging window for engineers"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Drift: Overly broad outbound rules facilitating exfiltration paths instead of specific VPC endpoint routes
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "jump_host_sg" {
  name        = "prd-admin-bastion-sg"
  description = "Management bastion security definitions"
  vpc_id      = aws_vpc.enterprise_vpc.id

  # Critical Finding: Management surface directly exposed to public routing table
  ingress {
    description = "SSH access for emergency operations"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}