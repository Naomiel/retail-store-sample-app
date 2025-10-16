# terraform {
  #required_providers {
   # aws = {
   #   source  = "hashicorp/aws"
    #  version = "~> 6.13.0"  # Latest as of Sep 2025
    #}
  #}
#}

provider "aws" {
  region = "us-west-2"
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", "us-west-2"]
  }
}

# VPC Configuration
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "bedrock-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-west-2a", "us-west-2b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true
}

# EKS Cluster
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "bedrock-cluster"
  cluster_version = "1.28"
  

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  eks_managed_node_groups = {
    worker = {
      min_size     = 2
      max_size     = 4
      desired_size = 2
      instance_types = ["t3.medium"]
      iam_role_additional_policies = {
        additional = aws_iam_policy.node_group_ec2.arn
      }
    }
  }

  enable_irsa = true
  cluster_encryption_config = {
    resources = ["secrets"]
  }
}

# IAM Policy for Node Group
resource "aws_iam_policy" "node_group_ec2" {
  name   = "BedrockEKSNodeGroupEC2Policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateTags",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeImages",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs"
        ]
        Resource = "*"
      }
    ]
  })
}

  # Ensure EKS cluster uses the IAM role
  #cluster_iam_role_arn = aws_iam_role.eks_cluster_role.arn

# IAM Role for EKS Cluster
resource "aws_iam_role" "eks_cluster_role" {
  name = "bedrock-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# Developer IAM User
#resource "aws_iam_user" "cicd_user" {
 # name = "bedrock-cicd-user"
#}

resource "aws_iam_user_policy" "cicd_user_policy" {
  name = "bedrock-cicd-policy"
  user = "bedrock-cicd-user"  # Reference the existing user
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["eks:*"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:Create*",
          "ec2:Describe*",
          "ec2:Delete*",
          "ec2:AllocateAddress",
          "ec2:AssociateAddress",
          "ec2:ReleaseAddress",
          "ec2:DescribeAddressesAttribute",
          "ec2:DetachNetworkInterface",
          "rds:*",
          "dynamodb:*",
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:CreateUser",
          "iam:CreatePolicy",
          "iam:DeleteRole",
          "iam:DeleteUser",
          "iam:DeletePolicy",
          "kms:*",
          "logs:CreateLogGroup",
          "logs:DescribeLogGroups",
          "logs:DeleteLogGroup",
          "logs:TagResource",
          "logs:PutRetentionPolicy",
          "logs:ListTagsForResource",
          "secretsmanager:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# EKS Access Entries for IAM Users
#resource "aws_eks_access_entry" "cicd_user" {
#  cluster_name      = module.eks.cluster_name
#  principal_arn     = "arn:aws:iam::124355637901:user/bedrock-cicd-user"
 # kubernetes_groups = ["cluster-admins"]
 # type              = "STANDARD"
#}

resource "aws_eks_access_entry" "developer_user" {
  cluster_name      = module.eks.cluster_name
  principal_arn     = "arn:aws:iam::124355637901:user/bedrock-developer"
  kubernetes_groups = ["cluster-admins"]
  type              = "STANDARD"
}

resource "kubernetes_cluster_role_binding" "cluster_admins" {
  metadata {
    name = "cluster-admins-binding"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    kind      = "Group"
    name      = "cluster-admins"
    api_group = "rbac.authorization.k8s.io"
  }
}

# Developer IAM User
resource "aws_iam_user" "developer" {
  name = "bedrock-developer"
}

resource "aws_iam_user_policy" "developer_policy" {
  name = "bedrock-developer-policy"
  user = aws_iam_user.developer.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters",
          "eks:DescribeNodegroup",
          "eks:ListNodegroups",
          "eks:AccessKubernetesApi"
        ]
        Resource = module.eks.cluster_arn
      }
    ]
  })
}

# Secrets Manager for RDS Credentials
data "aws_secretsmanager_secret_version" "orders_db" {
  secret_id = "bedrock-orders-db-credentials"
}

data "aws_secretsmanager_secret_version" "catalog_db" {
  secret_id = "bedrock-catalog-db-credentials"
}

# RDS for PostgreSQL
resource "aws_db_instance" "orders_db" {
  identifier           = "bedrock-orders-db"
  engine               = "postgres"
  engine_version       = "16.3"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = try(jsondecode(data.aws_secretsmanager_secret_version.orders_db.secret_string)["username"], "ordersuser")
  password             = try(jsondecode(data.aws_secretsmanager_secret_version.orders_db.secret_string)["password"], "securepassword123")
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name = aws_db_subnet_group.main.name
  skip_final_snapshot  = true
}

# RDS for MySQL
resource "aws_db_instance" "catalog_db" {
  identifier           = "bedrock-catalog-db"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = jsondecode(data.aws_secretsmanager_secret_version.catalog_db.secret_string)["username"]
  password             = jsondecode(data.aws_secretsmanager_secret_version.catalog_db.secret_string)["password"]
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name = aws_db_subnet_group.main.name
  skip_final_snapshot  = true
}

# DynamoDB
resource "aws_dynamodb_table" "carts" {
  name           = "bedrock-carts"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "cartId"

  attribute {
    name = "cartId"
    type = "S"
  }
}

# Security Group for RDS
resource "aws_security_group" "rds" {
  name   = "bedrock-rds-sg"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = module.vpc.private_subnets_cidr_blocks
  }
}

# RDS Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "bedrock-db-subnet-group"
  subnet_ids = module.vpc.private_subnets
}

####
# Ensure bedrock-cicd-user has admin access in the cluster
#resource "aws_eks_access_entry" "cicd_admin" {
 # cluster_name      = module.eks.cluster_name
#  principal_arn     = "arn:aws:iam::124355637901:user/bedrock-cicd-user"
 # kubernetes_groups = ["cluster-admins"]
#  type              = "STANDARD"
}

# Bind the cluster-admin ClusterRole to the cluster-admins group
#resource "kubernetes_cluster_role_binding" "cicd_admin_binding" {
#  metadata {
#    name = "bedrock-cicd-admin-binding"
#  }

#  role_ref {
#    api_group = "rbac.authorization.k8s.io"
#    kind      = "ClusterRole"
#    name      = "cluster-admin"
#  }

#  subject {
#    kind      = "Group"
#    name      = "cluster-admins"
#    api_group = "rbac.authorization.k8s.io"
#  }

#  depends_on = [aws_eks_access_entry.cicd_admin]
#}

# Grant EKS cluster access to bedrock-cicd-user
resource "aws_eks_access_entry" "cicd_admin" {
  cluster_name  = module.eks.cluster_name
  principal_arn = "arn:aws:iam::124355637901:user/bedrock-cicd-user"
  type          = "STANDARD"
}

# Attach admin policy to that access entry
resource "aws_eks_access_policy_association" "cicd_admin_policy" {
  cluster_name  = module.eks.cluster_name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = aws_eks_access_entry.cicd_admin.principal_arn

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.cicd_admin]
}