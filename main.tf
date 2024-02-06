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

# Learn our public IP address
# data "http" "icanhazip" {
#    url = "http://ipv4.icanhazip.com"
# }
# locals {
#   public_ip = "${chomp(data.http.icanhazip.body)}"
# }

# output "public_ip" {
#  value = "${local.public_ip}"
#   description = "My IP address"
#   sensitive   = true
# }

variable "key_name" {
	sensitive = true
}

variable "my_ip" {
	sensitive = true
}

  provider "aws" {
    region = "us-east-1"
  }

  /* instances */

  resource "aws_instance" "wazuh_server" {
    ami             = "ami-0c7217cdde317cfec"
    instance_type   = "t2.xlarge"
    key_name        = var.key_name
    vpc_security_group_ids  = [aws_security_group.wazuh_sg.id]
    subnet_id = aws_subnet.soc_subnet.id
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
    key_name        = var.key_name
    vpc_security_group_ids  = [aws_security_group.thehive_sg.id]
    subnet_id = aws_subnet.soc_subnet.id
    tags = {
      Name = "TheHiveServerInstance"
    }
    user_data = <<-EOL
					  #!/bin/bash -xe
					  apt update
					  apt -y wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb_release

					  wget -qO- https://apt.corretto.aws/corretto.key | gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
					  echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  tee -a /etc/apt/sources.list.d/corretto.sources.list
					  apt update
					  apt -y install java-common java-11-amazon-corretto-jdk
					  echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | tee -a /etc/environment 
					  export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

					  wget -qO -  https://downloads.apache.org/cassandra/KEYS | gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
					  echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  tee -a /etc/apt/sources.list.d/cassandra.sources.list 
					  apt update
					  apt -y install cassandra
					  sed -i "s/cluster_name: 'Test Cluster'/cluster_name: 'theHive'/g" /etc/cassandra/cassandra.yaml
					  systemctl stop cassandra
					  rm -rf /var/lib/cassandra/*
					  systemctl start cassandra

					  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
					  apt-get -y install apt-transport-https
					  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  tee /etc/apt/sources.list.d/elastic-7.x.list 
					  apt update
					  apt install elasticsearch

					  sed -i "s/#cluster.name: my-application/cluster.name: hive /g" /etc/cassandra/cassandra.yaml

					  EOL

  }

  /* networking */

  resource "aws_vpc" "soc_vpc" {
    cidr_block           = "10.5.0.0/16"
    #instance_tenancy     = "default"
    #enable_dns_hostnames = true
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
      cidr_blocks = ["${var.my_ip}/32"]
    }

    egress {
      from_port   = 0
      to_port     = 0
      protocol    = -1
      cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
      Name = "AWS_thehive_sg"
    }
  }

  resource "aws_security_group" "wazuh_sg" {
    name        = "AWS_wazuh_sg"
    description = "AWS_wazuh_sg"
    vpc_id      = aws_vpc.soc_vpc.id

    egress {
      from_port   = 0
      to_port     = 0
      protocol    = -1
      cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }

    ingress {
      from_port   = 1514
      to_port     = 1514
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }

    ingress {
      from_port   = 1515
      to_port     = 1515
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }
    
    ingress {
      from_port   = 1516
      to_port     = 1516
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }
    
    ingress {
      from_port   = 55000
      to_port     = 55000
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }
    
    ingress {
      from_port   = 9200
      to_port     = 9200
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }

    ingress {
      from_port   = 9300
      to_port     = 9400
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }

    ingress {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["${var.my_ip}/32"]
    }

    tags = {
      Name = "AWS_wazuh_sg"
    }
 }


