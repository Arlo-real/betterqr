# Production Setup Guide



## Prerequisites

- Ubuntu/Debian server with sudo access

- Domain name pointing to your server

- Node.js and npm installed: get it [here](https://nodejs.org/en/download)



## 1. Configure Environment



```bash

cd /path/to/betterqr

cp .env.example .env

```



Edit `.env` and set:

- `BASE_URL=https://yourdomain.com` (important for generated links)

- `PORT=3000` (internal port, Nginx will proxy to this)

- Adjust `MAX_FILE_SIZE_BYTES`, `SESSION_TIMEOUT_MS`, etc. as needed



## 2. Install Dependencies



```bash

npm install

```



## 3. Set Up SSL Certificate



```bash

sudo apt update

sudo apt install certbot python3-certbot-nginx -y



sudo certbot certonly --standalone -d yourdomain.com

```



Note the certificate paths (typically `/etc/letsencrypt/live/yourdomain.com/`)



## 4. Configure Nginx



Edit `/etc/nginx/sites-available/betterqr`:



```nginx

server {

    listen 80;

    listen [::]:80;

    server_name yourdomain.com;



    # Redirect HTTP to HTTPS

    return 301 https://$server_name$request_uri;

}



server {

    listen 443 ssl http2;

    listen [::]:443 ssl http2;

    server_name yourdomain.com;



    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;

    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;



    # Security headers

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;



    location / {

        proxy_pass http://127.0.0.1:3000;

        proxy_http_version 1.1;

        proxy_set_header Upgrade $http_upgrade;

        proxy_set_header Connection 'upgrade';

        proxy_set_header Host $host;

        proxy_set_header X-Real-IP $remote_addr;

        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_cache_bypass $http_upgrade;

    }

}

```



Enable the site:

```bash

sudo ln -s /etc/nginx/sites-available/betterqr /etc/nginx/sites-enabled/

```



Test and restart Nginx:

```bash

sudo nginx -t

sudo systemctl restart nginx

```







## 5. Auto-Renew SSL Certificates



```bash

sudo systemctl enable certbot.timer

sudo systemctl start certbot.timer

```




## 7. Add to autostart


## 6. Add to autostart

```bash

# Copy the service file to systemd

sudo cp /where-you-put-the-project/betterqr/betterqr.service /etc/systemd/system/



# Reload systemd to recognize the new service

sudo systemctl daemon-reload



# Enable auto-start on boot

sudo systemctl enable betterqr



# Start the service now

sudo systemctl start betterqr

```





### Useful commands:



Check if it's running:

```bash

sudo systemctl status betterqr

```



Restart the service:

```bash

sudo systemctl restart betterqr

```



View live logs:

```bash

sudo journalctl -u betterqr -f

```



Disable auto-start:

```bash

sudo systemctl disable betterqr

```










## 5. Alternative to systemd: start with PM2


## 7. Alternative to systemd: start with PM2 (not recommended)



```bash

sudo npm install -g pm2



pm2 start src/server.js --name betterqr

pm2 save

sudo pm2 startup

```



### Useful commands:



- Check PM2 status:

```bash

pm2 status

```

- View logs:

```bash

pm2 logs betterqr

```









## Troubleshooting



- **SSL errors**: Verify certificate paths in nginx config

- **File uploads fail**: Check permissions on `public/uploads/` directory

- **QR code not working**: Ensure `BASE_URL` in `.env` matches your domain