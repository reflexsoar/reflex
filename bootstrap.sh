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
starting_directory=$PWD

if [ ! -z "$uninstall" ]; then
    echo "Uninstalling reflex"
    echo "Removing reflex service"
    service reflex stop > /dev/null 2>&1
    rm -f /etc/systemd/system/reflex-api.service
    systemctl daemon-reload
    echo "Removing user reflex"
    userdel reflex
    rm -rf /home/reflex
    echo "Cleaning up files in /opt/reflex"
    rm -rf /opt/reflex
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
    MASTER_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    SECRET_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    SECURITY_PASSWORD_SALT=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    echo "Installing reflex"
    os_version=$(hostnamectl | grep "Operating System" | cut -d":" -f2 | cut -d" " -f2-)
    if [[ "$os" == "centos" ]]; then
        yum install -y python3-pip git
    fi
    if [[ "$os" == "ubuntu" ]]; then
        apt install -y python3-pip git
    fi
    pip3 install pipenv
    mkdir -p /opt/reflex/reflex-api
    cd /opt/reflex/reflex-api
    git clone --single-branch --branch dev https://github.com/reflexsoar/reflex-api.git .
    rm -rf /opt/reflex/reflex-api/migrations
    useradd reflex -m -s /bin/bash
    export FLASK_CONFIG="production"
    sudo --preserve-env=FLASK_CONFIG -u reflex bash -c "cd /opt/reflex/reflex-api; pipenv install --dev; pipenv run python manage.py db init; pipenv run python manage.py db migrate; pipenv run python manage.py db upgrade; pipenv run python manage.py setup;"
    echo "MASTER_PASSWORD=$MASTER_PASSWORD" > /opt/reflex/reflex-api/instance/application.conf
    echo "SECRET_KEY=$SECRET_KEY" >> /opt/reflex/reflex-api/instance/application.conf
    echo "SECURITY_PASSWORD_SALT=$SECURITY_PASSWORD_SALT" >> /opt/reflex/reflex-api/instance/application.conf
    chown -R reflex:reflex /opt/reflex
    chmod 400 /opt/reflex/reflex-api/instance/application.conf
    python_venv=$(sudo --preserve-env=FLASK_CONFIG -u reflex bash -c "cd /opt/reflex/reflex-api; pipenv --venv")
    echo "Python venv is : $python_venv"
fi
cd $starting_directory