terraform {

  /* providers */

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"

}

  provider "aws" {
    region = "us-east-1"
  }

  /* instances */

  resource "aws_instance" "wazuh_server" {
    ami             = "ami-0c7217cdde317cfec"
    instance_type   = "t2.xlarge"
    security_groups = ["AWS_wazuh_sg"]
    tags = {
      Name = "WazuhServerInstance"
    }
    user_data = <<-EOL
					  #!/bin/bash -xe
					  apt update
					  curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && bash ./wazuh-install.sh -a
					  EOL
  }

  resource "aws_instance" "thehive_server" {
    ami             = "ami-0c7217cdde317cfec"
    instance_type   = "t2.xlarge"
    security_groups = ["AWS_thehive_sg"]
    tags = {
      Name = "TheHiveServerInstance"
    }
    user_data = <<-EOL
					  #!/bin/bash -xe
					  apt-get update
					  apt-get install -y openjdk-8-jre-headless
					  echo JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64" >> /etc/environment
					  export JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
					  curl -fsSL https://www.apache.org/dist/cassandra/KEYS | apt-key add -
					  echo "deb http://www.apache.org/dist/cassandra/debian 311x main" | tee -a /etc/apt/sources.list.d/cassandra.sources.list
					  apt update
					  apt install cassandra
					  curl https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | apt-key add -
					  echo 'deb https://deb.thehive-project.org release main' | tee -a /etc/apt/sources.list.d/thehive-project.list
					  apt-get update
					  apt install thehive4
					  EOL

  }

  /* networking */

  resource "aws_vpc" "soc_vpc" {
    cidr_block           = "10.5.0.0/24"
    instance_tenancy     = "default"
    enable_dns_hostnames = true
    tags = {
      Name = "soc_vpc"
    }
  }

  resource "aws_internet_gateway" "soc_gw" {
    vpc_id = aws_vpc.soc_vpc.id
    tags = {
      Name = "soc gateway"
    }
  }

  resource "aws_subnet" "soc_subnet" {
    vpc_id                  = aws_vpc.soc_vpc.id
    cidr_block              = "10.5.0.0/24"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = true
    tags = {
      Name = "AWS_Soc subnet"
    }
  }

  resource "aws_route_table" "soc_rt" {
    vpc_id = aws_vpc.soc_vpc.id
    route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.soc_gw.id
    }
  }

  resource "aws_route_table_association" "soc_public_rta" {
    subnet_id      = aws_subnet.soc_subnet.id
    route_table_id = aws_route_table.soc_rt.id
  }

  /* security groups */

  resource "aws_security_group" "thehive_sg" {
    name        = "AWS_thehive_sg"
    description = "AWS_thehive_sg"
    vpc_id      = aws_vpc.soc_vpc.id
    ingress {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    tags = {
      Name = "AWS_thehive_sg"
    }
  }

  resource "aws_security_group" "wazuh_sg" {
    name        = "AWS_wazuh_sg"
    description = "AWS_wazuh_sg"
    vpc_id      = aws_vpc.soc_vpc.id
    ingress {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    ingress {
      to_port     = 1514
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    ingress {
      to_port     = 1515
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    ingress {
      to_port     = 1516
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    ingress {
      to_port     = 55000
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    ingress {
      to_port     = 9200
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    ingress {
      to_port     = 9300 - 9400
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    ingress {
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0/32"]
    }
    tags = {
      Name = "AWS_wazuh_sg"
    }
  }


