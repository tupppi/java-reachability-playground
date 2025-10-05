# Intentionally vulnerable Terraform configuration for IaC security testing
terraform {
  required_version = ">= 0.12"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  # Missing access key and secret key (vulnerability)
}

# Vulnerable S3 bucket - publicly accessible
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "super-vulnerable-bucket-${random_string.bucket_suffix.result}"
  
  # Public read access (vulnerability)
  acl = "public-read"
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
}

# Vulnerable S3 bucket policy - allows public access
resource "aws_s3_bucket_policy" "vulnerable_bucket_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
}

# Vulnerable EC2 instance - no security groups
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c02fb55956c7d316"  # Hardcoded AMI (vulnerability)
  instance_type = "t2.micro"
  
  # No security groups (vulnerability)
  # No IAM role (vulnerability)
  
  # User data with secrets (vulnerability)
  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo "DB_PASSWORD=super_secret_password_123" >> /etc/environment
    echo "API_KEY=sk-TEST_TOKEN_NOT_REAL" >> /etc/environment
    echo "AWS_SECRET_ACCESS_KEY=TEST_NOT_REAL_KEY" >> /etc/environment
  EOF
  )
  
  tags = {
    Name = "Vulnerable Instance"
    Environment = "production"  # Using production for test (vulnerability)
  }
}

# Vulnerable RDS instance - publicly accessible
resource "aws_db_instance" "vulnerable_database" {
  identifier = "vulnerable-db"
  
  engine         = "mysql"
  engine_version = "5.7"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp2"
  
  # Publicly accessible (vulnerability)
  publicly_accessible = true
  
  # Weak credentials (vulnerability)
  username = "admin"
  password = "admin123"
  
  # No encryption (vulnerability)
  storage_encrypted = false
  
  # No backup (vulnerability)
  backup_retention_period = 0
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"
  
  skip_final_snapshot = true
}

# Vulnerable security group - allows all traffic
resource "aws_security_group" "vulnerable_sg" {
  name_prefix = "vulnerable-sg-"
  description = "Vulnerable security group - allows all traffic"
  
  # Allow all inbound traffic (vulnerability)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Allow all outbound traffic (vulnerability)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "Vulnerable Security Group"
  }
}

# Vulnerable IAM role - overly permissive
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Vulnerable IAM policy - admin access
resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable-policy"
  role = aws_iam_role.vulnerable_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}
