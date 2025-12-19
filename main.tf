# This block configures Terraform itself, specifying the required AWS provider.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  # === NEW BACKEND CONFIGURATION ===
  backend "s3" {
    bucket = "wiz-tf-state-sswan30"   # Replace with the bucket name you just created
    key    = "terraform/state.tfstate"
    region = "us-east-1"
  }
}

# This block configures the specific settings for the AWS provider, such as the deployment region.
provider "aws" {
  region = "us-east-1"
}

# -----------------------------------------------------------------------------
# DYNAMIC AMI LOOKUP
# -----------------------------------------------------------------------------
# This looks up the latest Amazon Linux 2 AMI in your region automatically.
# It solves the "expired AMI" issue permanently.
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# This resource creates the main Virtual Private Cloud (VPC), which is an isolated network for your resources.
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "wiz-vpc" }
}

# This resource creates a public subnet, a subdivision of the VPC for resources that need internet access.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  # === FIX ADDED ===
  # These tags allow Kubernetes to identify this subnet as part of the
  # 'wiz-cluster' and mark it as usable for external load balancers.
  tags = {
    Name                                = "wiz-public-subnet"
    "kubernetes.io/cluster/wiz-cluster" = "shared"
    "kubernetes.io/role/elb"            = "1"
  }
}

# This resource creates a private subnet, a subdivision of the VPC for resources
# that should not be exposed to the internet.
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  # === FIX ADDED ===
  # (Original syntax error also fixed)
  # This tags the subnet as part of the cluster and, critically,
  # as a target for *internal* routing from the load balancer.
  tags = {
    Name                                = "wiz-private-subnet"
    "kubernetes.io/cluster/wiz-cluster" = "shared"
    "kubernetes.io/role/internal-elb"   = "1"
  }
}

# A second public subnet in AZ us-east-1b for the Classic Load Balancer
resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.3.0/24" # Using a new IP range (e.g., .3)
  availability_zone       = "us-east-1b"  # Same AZ as the private subnet
  map_public_ip_on_launch = true

  # === FIX ADDED ===
  # These tags are critical. The ELB needs a public subnet in the *same AZ*
  # (us-east-1b) as the private subnet (us-east-1b) where the nodes are.
  tags = {
    Name                                = "wiz-public-subnet-b"
    "kubernetes.io/cluster/wiz-cluster" = "shared"
    "kubernetes.io/role/elb"            = "1"
  }
}


# This resource creates an Internet Gateway, which provides a path for communication between your VPC and the internet.
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "wiz-igw" }
}

# This resource creates a route table, a set of rules that determines where network traffic is directed.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = { Name = "wiz-public-rt" }
}

# This resource associates the public route table with the public subnet, officially making it "public".
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}


# Associate the existing public route table with the new public subnet
resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id # Reuse the existing public route table
}


# This resource creates an Elastic IP, a static public IP address for our NAT Gateway.
resource "aws_eip" "nat" {
  vpc        = true
  depends_on = [aws_internet_gateway.gw]
}

# This resource creates the NAT Gateway and places it in our public subnet.
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  depends_on    = [aws_internet_gateway.gw]

  tags = {
    Name = "wiz-nat-gw"
  }
}

# This creates a new, dedicated route table for our private subnet.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # This rule directs all internet-bound traffic (0.0.0.0/0) to the NAT Gateway.
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "wiz-private-rt"
  }
}

# This associates our new private route table with our private subnet.
resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# This resource creates a Security Group, which acts as a virtual firewall for the database VM.
resource "aws_security_group" "db" {
  name        = "db-sg"
  description = "Allow SSH and MongoDB traffic"
  vpc_id      = aws_vpc.main.id

  # Allows nodes to talk to each other and the control plane for cluster operations.
  # (Fix EKS Node Group Stall)
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Intentionally insecure for the exercise
  }

  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    # CHANGE: Restrict specific access to the Private Subnet CIDR only
    cidr_blocks = [aws_subnet.private.cidr_block] 
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "wiz-db-sg" }
}

# This resource creates an IAM Role, which is an identity with permissions that the EC2 instance can assume.
resource "aws_iam_role" "db_role" {
  name = "db-instance-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

# This resource attaches a powerful permissions policy (AdministratorAccess) to the IAM role.
resource "aws_iam_role_policy_attachment" "db_role_admin_attachment" {
  role       = aws_iam_role.db_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # Intentionally insecure
}

# This resource creates a container for the IAM role, making it available to be attached to an EC2 instance.
resource "aws_iam_instance_profile" "db_profile" {
  name = "db-instance-profile"
  role = aws_iam_role.db_role.name
}

# -----------------------------------------------------------------------------
# DATABASE VM (Automated Setup)
# -----------------------------------------------------------------------------
resource "aws_instance" "db" {
  # 1. Use the dynamic AMI ID (from the data block we added at the top)
  ami           = data.aws_ami.amazon_linux_2.id 
  instance_type = "t2.micro"
  
  # 2. Key Pair & Identity
  key_name             = "wiz-db-key" 
  # This links the VM to the "AdministratorAccess" role 
  iam_instance_profile = aws_iam_instance_profile.db_profile.name 

  # 3. Network Configuration
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.db.id]
  associate_public_ip_address = true
  
  # 4. Define static private IP for Deployment.yaml to connect EKS
  private_ip                  = "10.0.1.50"

  tags = {
    Name = "wiz-database-vm"
  }

  # 4. Automation Script (User Data)
  user_data = <<-EOF
              #!/bin/bash
              set -e
              exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
              
              echo "--- STARTING AUTOMATED SETUP ---"

              # A. Install MongoDB 3.6
              cat <<EOT | tee /etc/yum.repos.d/mongodb-org-3.6.repo
              [mongodb-org-3.6]
              name=MongoDB Repository
              baseurl=https://repo.mongodb.org/yum/amazon/2/mongodb-org/3.6/x86_64/
              gpgcheck=1
              enabled=1
              gpgkey=https://www.mongodb.org/static/pgp/server-3.6.asc
              EOT

              yum install -y mongodb-org-3.6.23 mongodb-org-server-3.6.23 mongodb-org-shell-3.6.23 mongodb-org-mongos-3.6.23 mongodb-org-tools-3.6.23
              
              echo "Allowing remote connections..."
              sed -i 's/bindIp: 127.0.0.1/bindIp: 0.0.0.0/' /etc/mongod.conf

              service mongod start
              chkconfig mongod on
              sleep 10

              # --- STEP B: CREATE AUTHENTICATION ---
              echo "4. Creating Highly Privileged Tasky User..."
              
              # Create 'tasky_user' with ROOT permissions on the ADMIN database
              mongo admin --eval 'db.createUser({user: "tasky_user", pwd: "supersecretpassword", roles:[{role:"root",db:"admin"}]})'

              echo "5. Enabling Security Enforcement..."
              echo "security:
                authorization: enabled" >> /etc/mongod.conf

              echo "6. Restarting Mongo to lock the door..."
              service mongod restart

              # C. Setup Backups
              yum install -y aws-cli zip
              
              cat <<EOT > /home/ec2-user/backup.sh
              #!/bin/bash
              TIMESTAMP=\$(date +%F-%H%M)
              BACKUP_NAME="backup-\$TIMESTAMP.gz"
              mongodump --username tasky_user --password supersecretpassword --authenticationDatabase admin --archive=\$BACKUP_NAME --gzip
              aws s3 cp \$BACKUP_NAME s3://${aws_s3_bucket.backups.id}/\$BACKUP_NAME --acl public-read
              rm -f \$BACKUP_NAME
              EOT
              
              chmod +x /home/ec2-user/backup.sh
              chown ec2-user:ec2-user /home/ec2-user/backup.sh
              echo "0 * * * * /home/ec2-user/backup.sh" | crontab -u ec2-user -
              
              echo "--- SETUP COMPLETE ---"
              EOF
}



# This resource creates the S3 bucket.
resource "aws_s3_bucket" "backups" {
  bucket = "wiz-exercise-backups-sswan30"
  tags   = { Name = "wiz-db-backups" }
}

# This resource sets the bucket's ownership rules to allow ACLs.
resource "aws_s3_bucket_ownership_controls" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# This resource explicitly disables the "Block Public Access" settings for the bucket.
resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = false # Allows public ACLs
  block_public_policy     = false # Allows public policies
  ignore_public_acls      = false # Honors public ACLs
  restrict_public_buckets = false # Allows public buckets
}

# This resource applies the "public-read" canned ACL, making the bucket public.
resource "aws_s3_bucket_acl" "backups" {
  depends_on = [aws_s3_bucket_ownership_controls.backups]
  bucket     = aws_s3_bucket.backups.id
  acl        = "public-read" # Intentionally insecure
}

# -----------------------------------------------------------------------------
# EKS (Kubernetes) Cluster
# -----------------------------------------------------------------------------

# IAM Role for the EKS Cluster itself
resource "aws_iam_role" "eks_cluster_role" {
  name = "wiz-eks-cluster-role"

  # Trust policy that allows the EKS service to assume this role
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "eks.amazonaws.com"
        }
      },
    ]
  })
}

# Attaches the required AWS-managed policy to the cluster role
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# IAM Role for the EKS Worker Nodes (the VMs that run your containers)
resource "aws_iam_role" "eks_node_role" {
  name = "wiz-eks-node-role"

  # Trust policy that allows EC2 instances to assume this role
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# Attaches the required policies for the worker nodes
resource "aws_iam_role_policy_attachment" "eks_node_worker_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_node_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_node_ecr_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_role.name
}

# This is the main EKS Cluster resource
resource "aws_eks_cluster" "cluster" {
  name     = "wiz-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  # Specifies which subnets the cluster can use for networking
  vpc_config {
    # === FIX ADDED ===
    # The EKS control plane needs to know about *all* subnets it will use,
    # including both public subnets for the ELB and the private for nodes.
    subnet_ids = [aws_subnet.private.id, aws_subnet.public.id, aws_subnet.public_b.id]
  }

# Allows hybrid mode for AWS User auth
access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }


  # Ensures the IAM role is fully created before the cluster
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
  ]
}

# This resource defines the group of EC2 instances that will be the worker nodes
resource "aws_eks_node_group" "nodes" {
  cluster_name    = aws_eks_cluster.cluster.name
  node_group_name = "wiz-node-group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [aws_subnet.private.id] # Place worker nodes in the private subnet

  # Using a slightly larger instance type, as t2.micro can be too small for EK
  instance_types = ["t3.small"]

  # Defines how many worker nodes to run
  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_node_worker_policy,
    aws_iam_role_policy_attachment.eks_node_cni_policy,
    aws_iam_role_policy_attachment.eks_node_ecr_policy,
  ]
}

# -----------------------------------------------------------------------------
# ECR (Elastic Container Registry)
# -----------------------------------------------------------------------------

# This resource creates a repository to store our container images
resource "aws_ecr_repository" "app" {
  name = "wiz-app-repo"
  tags = {
    Name = "wiz-app-repo"
  }
}

# -------Granting my AWS User Cluster Admin Permissions--------

# 1. Add your IAM User to the cluster's "Guest List"
resource "aws_eks_access_entry" "console_user" {
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn     = "arn:aws:iam::149536462665:user/Sean"
  type              = "STANDARD"
}

# 2. Grant that user "Cluster Admin" permissions
resource "aws_eks_access_policy_association" "console_admin" {
  cluster_name      = aws_eks_cluster.cluster.name
  principal_arn     = aws_eks_access_entry.console_user.principal_arn
  policy_arn        = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }
}
