# Production Setup Guide

## Prerequisites
- Ubuntu/Debian server with sudo access
- Domain name pointing to your server
- Node.js and npm installed get it [here](https://nodejs.org/en/download)

## 1. Configure Environment

```bash
cd /path/to/reverseqr
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

Edit `/etc/nginx/sites-available/reverseqr`:

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
sudo ln -s /etc/nginx/sites-available/reverseqr /etc/nginx/sites-enabled/
```

Test and restart Nginx:
```bash
sudo nginx -t
sudo systemctl restart nginx
```

## 5. Start with PM2

```bash
sudo npm install -g pm2

pm2 start src/server.js --name reverseqr
pm2 save
sudo pm2 startup
```

## 6. Auto-Renew SSL Certificates

```bash
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

## Verification

- Visit `https://yourdomain.com` in browser
- Check PM2 status: `pm2 status`
- View logs: `pm2 logs reverseqr`

## Troubleshooting

- **Port 3000 not responding**: Check firewall, ensure PM2 is running
- **SSL errors**: Verify certificate paths in nginx config
- **File uploads fail**: Check permissions on `public/uploads/` directory
- **QR code not working**: Ensure `BASE_URL` in `.env` matches your domain
