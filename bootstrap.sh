#!/bin/bash
while [ "$1" != "" ]; do
    case $1 in
        -u | --uninstall )           shift
                                filename="$1"
                                ;;
        -h | --help )           usage
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done

cleanup=${environment:-cleanup}
if [ "$EUID" -ne 0 ]
  then echo "Please run with sudo"
  exit
fi
os_version=$(hostnamectl | grep "Operating System" | cut -d":" -f2 | cut -d" " -f2-)
if [[ "$os_version" == "CentOS"* ]]; then
  os="centos"
  yum install -y python3-pip wget unzip
fi
if [[ "$os_version" == "Ubuntu"* ]]; then
  os="ubuntu"
  apt install -y python3-pip wget unzip
fi
pip3 install pipenv
wget https://www.hasecuritysolutions.com/reflex_1.0.zip -O /opt/reflex.zip
cd /opt
unzip reflex.zip
rm -f reflex.zip