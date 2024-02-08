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

variable "default_thehive_user" {
  sensitive = true
}

variable "default_thehive_password" {
  sensitive = true
}

variable "myorg_thehive_user_analyst_password" {
  sensitive = true
}

variable "myorg_thehive_user_admin_password" {
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
            apt install -y wget 
					  curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && bash ./wazuh-install.sh -a
            /var/ossec/framework/python/bin/pip3 install thehive4py==1.8.1

            wget https://raw.githubusercontent.com/OpenSecureCo/Demos/main/linux-sysmon.xml -P /var/ossec/etc/decoders/
            wget https://raw.githubusercontent.com/OpenSecureCo/Demos/main/sysmonforlinux-rules.xml -P /var/ossec/etc/rules/
            wget https://raw.githubusercontent.com/frenzymilk/soc_automation_project/main/custom-w2thive -P /var/ossec/integrations/custom-w2thive
            wget https://raw.githubusercontent.com/frenzymilk/soc_automation_project/main/custom-w2thive.py -P /var/ossec/integrations/custom-w2thive.py

            chmod 755 /var/ossec/integrations/custom-w2thive.py
            chmod 755 /var/ossec/integrations/custom-w2thive
            chown root:ossec /var/ossec/integrations/custom-w2thive.py
            chown root:ossec /var/ossec/integrations/custom-w2thive
            
            systemctl restart wazuh-manager
					  
            EOL
}

resource "aws_instance" "target_server" {
    ami             = "ami-0c7217cdde317cfec"
    instance_type   = "t2.micro"
    key_name        = var.key_name
    vpc_security_group_ids  = [aws_security_group.target_sg.id]
    subnet_id = aws_subnet.target_subnet.id
    tags = {
      Name = "TargetServerInstance"
    }
    user_data = <<-EOL
					  #!/bin/bash -xe
					  apt-get update
					  apt-get install -y curl wget
					  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
					  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
					  apt-get update 
					  WAZUH_MANAGER="${aws_instance.wazuh_server.private_ip}" apt-get install wazuh-agent
					  systemctl daemon-reload
					  systemctl enable wazuh-agent
					  systemctl start wazuh-agent
					  sed -i "s/^deb/#deb/" /etc/apt/sources.list.d/wazuh.list
					  apt-get update

					  wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
					  dpkg -i packages-microsoft-prod.deb
					  apt-get update
					  apt-get install -y  sysmonforlinux

					  printf '%s\n' '<Sysmon schemaversion="4.70">' \
					    '<EventFiltering>' \
					      '<!-- Event ID 1 == ProcessCreate. Log all newly created processes -->' \
					      '<RuleGroup name="" groupRelation="or">' \
					        '<ProcessCreate onmatch="exclude"/>' \
					      '</RuleGroup>' \
					      '<!-- Event ID 3 == NetworkConnect Detected. Log all network connections -->' \
					      '<RuleGroup name="" groupRelation="or">' \
					        '<NetworkConnect onmatch="exclude"/>' \
					      '</RuleGroup>' \
					      '<!-- Event ID 5 == ProcessTerminate. Log all processes terminated -->' \
					      '<RuleGroup name="" groupRelation="or">' \
					        '<ProcessTerminate onmatch="exclude"/>' \
					      '</RuleGroup>' \
					      '<!-- Event ID 9 == RawAccessRead. Log all raw access read -->' \
					      '<RuleGroup name="" groupRelation="or">' \
					        '<RawAccessRead onmatch="exclude"/>' \
					      '</RuleGroup>' \
					      '<!-- Event ID 10 == ProcessAccess. Log all open process operations -->' \
					      '<RuleGroup name="" groupRelation="or">' \
					        '<ProcessAccess onmatch="exclude"/>' \
					      '</RuleGroup>' \
					      '<!-- Event ID 11 == FileCreate. Log every file creation -->' \
					      '<RuleGroup name="" groupRelation="or">' \
					        '<FileCreate onmatch="exclude"/>' \
					      '</RuleGroup>' \
					      '<!--Event ID 23 == FileDelete. Log all files being deleted -->' \
					      '<RuleGroup name="" groupRelation="or">' \
					        '<FileDelete onmatch="exclude"/>' \
					      '</RuleGroup>' \
					    '</EventFiltering>' \
					  '</Sysmon>' >> /opt/sysmon_config.xml

					  sysmon -accepteula -i /opt/sysmon_config.xml
					  
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
					  apt install -y wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release

					  wget -qO- https://apt.corretto.aws/corretto.key | gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
					  echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  tee -a /etc/apt/sources.list.d/corretto.sources.list
					  apt update
					  apt install -y  java-common java-11-amazon-corretto-jdk
					  echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | tee -a /etc/environment 
					  export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

					  wget -qO -  https://downloads.apache.org/cassandra/KEYS | gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
					  echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  tee -a /etc/apt/sources.list.d/cassandra.sources.list 
					  apt update
					  apt install -y  cassandra
					  sed -i "s/cluster_name: 'Test Cluster'/cluster_name: 'theHive'/g" /etc/cassandra/cassandra.yaml
					  systemctl stop cassandra
					  rm -rf /var/lib/cassandra/*
					  systemctl start cassandra

					  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
					  apt-get install  -y apt-transport-https
					  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  tee /etc/apt/sources.list.d/elastic-7.x.list 
					  apt update
					  apt -y install elasticsearch
					  sed -i "s/#cluster.name: my-application/cluster.name: hive /g" /etc/elasticsearch/elasticsearch.yml
					  echo  "http.host: 127.0.0.1" >> /etc/elasticsearch/elasticsearch.yml
					  echo  "transport.host: 127.0.0.1" >> /etc/elasticsearch/elasticsearch.yml
					  echo  "thread_pool.search.queue_size: 100000" >> /etc/elasticsearch/elasticsearch.yml
					  echo  "script.allowed_types: \"inline,stored\"" >> /etc/elasticsearch/elasticsearch.yml
					  echo  "xpack.security.enabled: false" >> etc/elasticsearch/elasticsearch.yml
					  touch /etc/elasticsearch/jvm.options.d/jvm.options
					  echo "-Dlog4j2.formatMsgNoLookups=true" >> /etc/elasticsearch/jvm.options.d/jvm.options
					  echo "-Xms4g" >> /etc/elasticsearch/jvm.options.d/jvm.options
					  echo "-Xmx4g" >> /etc/elasticsearch/jvm.options.d/jvm.options
					  systemctl stop elasticsearch
					  rm -rf /var/lib/elasticsearch/*
					  systemctl start elasticsearch
					  systemctl enable elasticsearch

					  wget -O- https://archives.strangebee.com/keys/strangebee.gpg | gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
					  echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | tee -a /etc/apt/sources.list.d/strangebee.list
					  apt-get update
					  apt-get install -y thehive
					  mkdir -p /opt/thp/thehive/files
					  chown -R thehive:thehive /opt/thp/thehive/files
					  systemctl start thehive
					  systemctl enable thehive

            curl -u ${var.default_thehive_user}:${var.default_thehive_password} -X POST -d  {"name": "myOrg", "description": "SOC automation"} http://${aws_instance.thehive_server.public_ip}:9000/api/v1/organisation 

            curl -u ${var.default_thehive_user}:${var.default_thehive_password} -X POST -d  {"login": "myorguseradmin@myorg.com", "name": "myOrgUserAdmin", "password":${var.myorg_thehive_user_admin_password}, "profile": "org-admin", "organisation": "myOrg"} http://${aws_instance.thehive_server.public_ip}:9000/api/v1/user

            curl -u ${var.default_thehive_user}:${var.default_thehive_password} -X POST -d  {"login": "myorguseranalyst@myorg.com", "name": "myOrgUserAnalyst", "password":${var.myorg_thehive_user_analyst_password}, "profile": "analyst", "organisation": "myOrg"} http://${aws_instance.thehive_server.public_ip}:9000/api/v1/user

            curl -u ${var.default_thehive_user}:${var.default_thehive_password} -X POST  http://${aws_instance.thehive_server.public_ip}:9000/api/v1/user/myOrgUser/key/renew

					  EOL

}

  /* networking */

  resource "aws_vpc" "target_vpc" {
    cidr_block           = "10.4.0.0/16"
    #instance_tenancy     = "default"
    #enable_dns_hostnames = true
    tags = {
      Name = "target_vpc"
    }
  }

  resource "aws_subnet" "target_subnet" {
    vpc_id                  = aws_vpc.target_vpc.id
    cidr_block              = "10.4.0.0/24"
    availability_zone       = "us-east-1a"
    map_public_ip_on_launch = true
    tags = {
      Name = "AWS_Soc subnet"
    }
  }

  resource "aws_internet_gateway" "target_gw" {
    vpc_id = aws_vpc.target_vpc.id
    tags = {
      Name = "target gateway"
    }
  }

  resource "aws_route_table" "target_rt" {
    vpc_id = aws_vpc.target_vpc.id
    route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.target_gw.id
    }
    route {
      cidr_block = aws_vpc.soc_vpc.cidr_block
      vpc_peering_connection_id = aws_vpc_peering_connection.target_soc.id
    }
  }

  resource "aws_route_table_association" "target_public_rta" {
    subnet_id      = aws_subnet.target_subnet.id
    route_table_id = aws_route_table.target_rt.id
  }

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
    route {
      cidr_block = aws_vpc.target_vpc.cidr_block
      vpc_peering_connection_id = aws_vpc_peering_connection.target_soc.id
    }
  }

  resource "aws_route_table_association" "soc_public_rta" {
    subnet_id      = aws_subnet.soc_subnet.id
    route_table_id = aws_route_table.soc_rt.id
  }

  resource "aws_vpc_peering_connection" "target_soc" {
    peer_vpc_id   = aws_vpc.soc_vpc.id
    vpc_id        = aws_vpc.target_vpc.id
    auto_accept   = true
  }

  /* security groups */

  resource "aws_security_group" "target_sg" {
    name        = "AWS_target_sg"
    description = "AWS_target_sg"
    vpc_id      = aws_vpc.target_vpc.id

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
      Name = "AWS_target_sg"
    }
  }

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

    ingress {
      from_port   = 9000
      to_port     = 9000
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
      #cidr_blocks = ["${aws_instance.target_server.private_ip}/32"]
      security_groups = [aws_security_group.target_sg.id]
    }

    ingress {
      from_port   = 1515
      to_port     = 1515
      protocol    = "tcp"
      #cidr_blocks = ["${aws_instance.target_server.private_ip}/32"]
      security_groups = [aws_security_group.target_sg.id]
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


