#!/bin/bash
os_version=$(hostnamectl | grep "Operating System" | cut -d":" -f2 | cut -d" " -f2-)
if [[ "$os_version" == "CentOS"* ]]; then
  $os="centos"
fi
if [[ "$os_version" == "Ubuntu"* ]]; then
  $os="ubuntu"
fi
echo $os