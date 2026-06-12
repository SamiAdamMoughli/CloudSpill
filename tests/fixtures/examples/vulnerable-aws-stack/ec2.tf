# EC2-003: IMDSv2 not required — vulnerable to SSRF credential theft
# EC2-004: Public IP enabled
resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_app.name
  associate_public_ip_address = true

  # IMDSv2 not enforced — http_tokens should be "required"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  user_data = <<-EOF2
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
  EOF2

  tags = {
    Name        = "${var.project}-web-server"
    Environment = var.environment
  }
}

# Second instance — same problems, in different AZ
resource "aws_instance" "web_b" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.public_b.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_app.name
  associate_public_ip_address = true

  tags = {
    Name        = "${var.project}-web-server-b"
    Environment = var.environment
  }
}
