# reflex
Reflex SOAR

## Production Deployment

1. Download latest `reflex-api` version
2. Install dependencies `pipenv install --dev`
3. Setup database

```
pipenv run python manage.py db init
pipenv run python manage.py db migrate
pipenv run python manage.py db upgrade
```

4. Run initial DB setup `pipenv run python manage.py setup`

5. Add instance/application.conf to the API folder
6. Create the reflex linux user
7. Assign owner to all reflex-api files `chown -R reflex:reflex /opt/reflex/reflex-api`
8. Create service file for API  `sudo nano /etc/systemd/system/reflex-api.service`

```
[Unit]
Description=Gunicorn instance to server Reflex API
After=network.target

[Service]
User=reflex
Group=www-data
WorkingDirectory=/opt/reflex/reflex-api
Environment="PATH=/home/reflex/.local/share/virtualenvs/reflex-api-Efq6sol1/bin"
ExecStart=/home/reflex/.local/share/virtualenvs/reflex-api-Efq6sol1/bin/gunicorn --workers 3 --bind unix:reflex-api.sock -m 007 'app:create_app()'

[Install]
WantedBy=multi-user.target
```

9. Reload and start `reflex-api` with `systemctl daemon-reload && systemctl start reflex-api`
10. Create folder for front end `/opt/reflex/ui`
11. Configure NGINX
```
server {
   listen 80;
   server_name staging.reflexsoar.com;

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
}
```

12. Get certificate via certbot
```
sudo apt install certbot python3-certbot-nginx
certbot --nginx -d staging.reflexsoar.com
```
