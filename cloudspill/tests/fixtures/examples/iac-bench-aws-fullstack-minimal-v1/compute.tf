# Application compute tier
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = false
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail

    dnf update -y
    dnf install -y nginx

    cat >/usr/share/nginx/html/index.html <<'HTML'
    <html>
      <head><title>IAC Benchmark App</title></head>
      <body>
        <h1>Service Ready</h1>
        <p>Minimal fullstack application host.</p>
      </body>
    </html>
    HTML

    systemctl enable nginx
    systemctl restart nginx
  EOF
  )

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "${local.name_prefix}-app-node"
      Role = "application"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name = "${local.name_prefix}-app-volume"
      Role = "application"
    }
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${local.name_prefix}-asg"
  min_size                  = 2
  max_size                  = 4
  desired_capacity          = 2
  vpc_zone_identifier       = aws_subnet.private_app[*].id
  health_check_type         = "ELB"
  health_check_grace_period = 120
  target_group_arns         = [aws_lb_target_group.app.arn]

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-asg-node"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "application"
    propagate_at_launch = true
  }
}

resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.admin.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2.name

  tags = {
    Name = "${local.name_prefix}-bastion"
    Role = "maintenance"
  }
}