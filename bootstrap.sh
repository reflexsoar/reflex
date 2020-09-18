#!/bin/bash
while getopts ":uh" flag
do
    case "${flag}" in
        u) uninstall=true ;;
        i) install=true ;;
        h) echo "usage: $0 [-h] [-u uninstall] [-i install (default is to install)]"; exit ;;
    esac
done

if [ ! -z "$uninstall" ] && [ ! -z "$install" ]; then
    echo "You cannot use -i and -u at the same time"
    exit
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root"
    exit
fi

os_version=$(hostnamectl | grep "Operating System" | cut -d":" -f2 | cut -d" " -f2-)
if [[ "$os_version" == "CentOS"* ]]; then
    os="centos"
fi
if [[ "$os_version" == "Ubuntu"* ]]; then
    os="ubuntu"
fi
if [ "$os" != "centos" ] && [ "$os" != "ubuntu" ]; then
    echo "This script is only supported on centos and ubuntu"
    exit
fi

if [ ! -z "$uninstall" ]; then
    echo "Uninstalling reflex"
    service reflex stop > /dev/null 2>&1
    userdel reflex
    rm -rf /opt/reflex
    rm -f /etc/systemd/system/reflex-api.service
    systemctl daemon-reload
    echo "Nginx is not removed as part of this script due to potentially removing a production web site."
    echo "To uninstall nginx, run the below command(s):"
    if [ "$os" == "centos" ]; then
        echo "yum remove nginx"
    else
        echo "apt remove -f nginx"
        echo "apt purge nginx"
    fi
fi

if [ -z "$install"] && [ ! -z "$uninstall" ]; then
    install=true
fi

if [ -z "$install" ]; then
    echo "Installing reflex"
    os_version=$(hostnamectl | grep "Operating System" | cut -d":" -f2 | cut -d" " -f2-)
    if [[ "$os" == "centos" ]]; then
        yum install -y python3-pip wget unzip
    fi
    if [[ "$os" == "ubuntu" ]]; then
        apt install -y python3-pip wget unzip
    fi
    pip3 install pipenv
    wget https://www.hasecuritysolutions.com/reflex_1.0.zip -O /opt/reflex.zip
    unzip /opt/reflex.zip -d /opt
    rm -f /opt/reflex.zip
    useradd reflex -m -s /bin/bash 
    chown -R reflex /opt/reflex
    export FLASK_CONFIG="production"
    export PIPENV_PIPFILE=/home/reflex/Pipfile
    sudo --preserve-env=FLASK_CONFIG --preserve-env=PIPENV_PIPFILE -u reflex pipenv run python /opt/reflex/reflex-api/manage.py db init
fi