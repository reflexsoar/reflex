#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run with sudo"
  exit
fi
os_version=$(hostnamectl | grep "Operating System" | cut -d":" -f2 | cut -d" " -f2-)
if [[ "$os_version" == "CentOS"* ]]; then
  os="centos"
  yum install -y python3-pip
fi
if [[ "$os_version" == "Ubuntu"* ]]; then
  os="ubuntu"
  apt install -y python3-pip
fi
pip3 install pipenv
echo $os