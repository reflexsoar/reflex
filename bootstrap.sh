#!/bin/bash
while getopts ":uih" flag
do
    case "${flag}" in
        u) uninstall=true ;;
        i) install=true ;;
        h) echo "usage: $0 [-h] [-u uninstall] [-i install (default is to install)]"; exit ;;
    esac
done

#if [ ! -z "$uninstall" ] && [ ! -z "$install" ]; then
#    echo "You cannot use -i and -u at the same time"
#    exit
#fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo or as root"
    exit
fi

os_version=$(hostnamectl | grep "Operating System" | cut -d":" -f2 | cut -d" " -f2-)
if [[ "$os_version" == "Ubuntu"* ]]; then
    os="ubuntu"
fi
if [ "$os" != "ubuntu" ]; then
    echo "This script is only supported on ubuntu"
    exit
fi
starting_directory=$PWD

if [ ! -z "$uninstall" ]; then
    echo "Uninstalling reflex"
    echo "Removing reflex service"
    service reflex-api stop > /dev/null 2>&1
    rm -f /etc/systemd/system/reflex-api.service
    systemctl daemon-reload
    echo "Removing user reflex"
    userdel reflex
    rm -rf /home/reflex
    rm -rf /var/spool/mail/reflex
    echo "Cleaning up files in /opt/reflex"
    rm -rf /opt/reflex
    echo "Nginx is not removed as part of this script due to potentially removing a production web site."
    echo "To uninstall nginx, run the below command(s):"
    echo "apt remove -f nginx"
    echo "apt purge nginx"
fi

if [ -z "$install" ] && [ -z "$uninstall" ]; then
    install=true
fi

if [ ! -z "$install" ]; then
    MASTER_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 128 | head -n 1)
    SECRET_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 512 | head -n 1)
    SECURITY_PASSWORD_SALT=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 512 | head -n 1)
    echo "Installing reflex"
    if [[ "$os" == "ubuntu" ]]; then
        apt install -y python3-pip git nginx libpq-dev python3-dev
    fi
    mkdir -p /opt/reflex/reflex-api
    cd /opt/reflex/reflex-api
    git clone --single-branch --branch dev https://github.com/reflexsoar/reflex-api.git .
    rm -rf /opt/reflex/reflex-api/migrations
    useradd reflex -m -s /bin/bash
    export FLASK_CONFIG="development"
    chown -R reflex:reflex /opt/reflex
    sudo --preserve-env=FLASK_CONFIG -u reflex pip3 install pipenv
    sudo --preserve-env=FLASK_CONFIG -u reflex bash -c "cd /opt/reflex/reflex-api; /usr/local/bin/pipenv install --dev; /usr/local/bin/pipenv run python manage.py db init; /usr/local/bin/pipenv run python manage.py db migrate; /usr/local/bin/pipenv run python manage.py db upgrade; /usr/local/bin/pipenv run python manage.py setup;"
    mkdir -p /opt/reflex/reflex-api/instance
    echo "MASTER_PASSWORD = '$MASTER_PASSWORD'" > /opt/reflex/reflex-api/instance/application.conf
    echo "SECRET_KEY = '$SECRET_KEY'" >> /opt/reflex/reflex-api/instance/application.conf
    echo "SECURITY_PASSWORD_SALT = '$SECURITY_PASSWORD_SALT'" >> /opt/reflex/reflex-api/instance/application.conf
    chown -R reflex:reflex /opt/reflex
    chmod 400 /opt/reflex/reflex-api/instance/application.conf
    python_venv=$(sudo --preserve-env=FLASK_CONFIG -u reflex bash -c "cd /opt/reflex/reflex-api; pipenv --venv")
    cpu_cores=$(grep -c processor /proc/cpuinfo)
    echo "[Unit]
Description=Gunicorn instance to server Reflex API
After=network.target

[Service]
User=reflex
Group=www-data
WorkingDirectory=/opt/reflex/reflex-api
Environment=\"PATH=$python_venv/bin\"
ExecStart=$python_venv/bin/gunicorn --workers $cpu_cores --bind unix:reflex-api.sock -m 007 'app:create_app(\"development\")'

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/reflex-api.service
    systemctl daemon-reload
    service reflex-api start

    # Set up Reflex UI
    mkdir -p /opt/reflex/ui
    cd /opt/reflex
    wget https://github.com/reflexsoar/reflex-ui/releases/download/0.1/ui.zip
    unzip ui.zip
    rm -f ui.zip
    chown -R reflex:reflex /opt/reflex/ui

    mkdir -p /opt/reflex/ssl
    openssl dhparam -dsaparam -out /opt/reflex/ssl/ssl-dhparams.pem 4096
    openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
                -subj "/C=US/ST=IL/O=H & A Security Solutions, LLC/CN=reflexsoar" \
                -keyout /opt/reflex/ssl/server.key  -out /opt/reflex/ssl/server.crt

    echo 'server {
   server_name reflexsoar;

   location /api/v1.0 {
        proxy_pass http://unix:/opt/reflex/reflex-api/reflex-api.sock;
        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout   600;
        proxy_send_timeout      600;
        proxy_read_timeout      600;
        send_timeout            600;
   }

   location / {
        alias /opt/reflex/ui/;
        index index.html;
   }


    listen 443 ssl;
    ssl_certificate /opt/reflex/ssl/server.crt;
    ssl_certificate_key /opt/reflex/ssl/server.key;
    ssl_session_cache shared:le_nginx_SSL:10m;
    ssl_session_timeout 1440m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA";
    ssl_dhparam /opt/reflex/ssl/ssl-dhparams.pem;

}
server {
    if ($host = reflexsoar) {
        return 301 https://$host$request_uri;
    }


   listen 80;
   server_name reflexsoar;
    return 404;


}' > /etc/nginx/conf.d/reflex.conf
    service nginx restart
fi
cd $starting_directory
