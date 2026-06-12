# ECS Compute Container Configurations

resource "aws_ecs_cluster" "platform_cluster" {
  name = "enterprise-core-platform"
}

# =========================================================================
# VULNERABILITY SEED: Theme 4 (Internal Service Trust) & Theme 9 (Supply-Chain/Privileged)
# =========================================================================
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-core-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ecs_broad_s3" {
  name = "ecs-app-s3-trust-policy"
  role = aws_iam_role.ecs_task_execution_role.id

  # Internal Service Trust Defect: App instance requires access to one folder, given root bucket control
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "dynamodb:*"]
      Resource = "*"
    }]
  })
}

resource "aws_ecs_task_definition" "app_worker" {
  family                   = "enterprise-core-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["EC2"]
  cpu                      = "512"
  memory                   = "1024"
  task_role_arn            = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "worker-service"
      image     = "docker.io/library/ubuntu:latest" # Supply-chain flaw: unpinned third party public registry
      privileged = true                            # Supply-chain/Isolation flaw: Escapes container virtualization boundaries
      essential = true
      portMappings = [{
        containerPort = 8080
        hostPort      = 8080
      }]
    }
  ])
}


# VULNERABILITY SEED: Theme 10 (Metadata Protection Weakness)
resource "aws_launch_template" "ecs_capacity_template" {
  name_prefix   = "ecs-compute-launch-template-"
  image_id      = "ami-0c55b159cbfafe1f0" # Dummy AMI ID for graph processing
  instance_type = "m5.large"

  # Structural Weakness: Enabling IMDSv1 exposes tokens via SSRF vectors
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}