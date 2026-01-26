```
╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║    ▓▓▓▓▓▓▓        ╔═╗ ╦ ╦ ╔═╗ ╔═╗ ╦ ╦ ╔═╗ ╦═╗ ╔╦╗               ║
║   ▓▓(• •)▓▓       ╚═╗ ╠═╣ ╠═  ╠═╝ ╠═╣ ╠═  ╠╦╝  ║║               ║
║    ▓▓▓▓▓▓▓        ╚═╝ ╩ ╩ ╚═╝ ╩   ╩ ╩ ╚═╝ ╩╚═ ═╩╝               ║
║    ┃┃  ┃┃         External Attack Surface Management            ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/Cameleon037/shepherd
cd shepherd
cp shepherd/clean_settings.py shepherd/settings.py
# Set DEBUG to False for Production

python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
./clean_all.sh

# Start server
python3 manage.py runserver 127.0.0.1:80
```

---

## 📦 Dependencies

<details>
<summary><b>System packages (as root)</b></summary>

```bash
apt install nmap redis npm
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt install ./google-chrome-stable_current_amd64.deb
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz -O /tmp/go1.24.4.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go1.24.4.linux-amd64.tar.gz
```

</details>

<details>
<summary><b>Go and other tools (as www-data)</b></summary>

```bash
mkdir /var/www/
sudo chown -R www-data:www-data /var/www/
sudo -u www-data bash

export PATH=/opt/shepherd/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/local/go/bin:/var/www/go/bin
cd ~
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

cd /var/www/
git clone https://github.com/tillson/git-hound
cd git-hound
wget https://github.com/tillson/git-hound/releases/download/v3.2/git-hound_linux_amd64.zip
unzip git-hound_linux_amd64.zip
# modify the config.yml to use a valid github access token
```

</details>

<details>
<summary><b>AI capabilities (optional)</b></summary>

```bash
sudo -u www-data bash
cd ~
touch ~/.bashrc
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install node
npx @playwright/mcp@latest  # Enter (y) to install Playwright MCP
```

</details>

---

## 🏭 Production Deployment

### Initial Setup

```bash
# As root
cd /opt
git clone https://github.com/Cameleon037/shepherd
cp shepherd/clean_settings.py shepherd/settings.py
chown -R www-data:www-data /opt/shepherd/
apt install python3-pip python3-venv libpq-dev postgresql postgresql-contrib nginx

cd /opt/shepherd
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

# As www-data
sudo -u www-data bash
source venv/bin/activate
playwright install
```

### PostgreSQL Setup

```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE shepherddb;
CREATE USER shepherd WITH PASSWORD 'mypassword';
ALTER ROLE shepherd SET client_encoding TO 'utf8';
ALTER ROLE shepherd SET default_transaction_isolation TO 'read committed';
ALTER ROLE shepherd SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE shepherddb TO shepherd;
\q
```

### Configuration Files

<details>
<summary><code>shepherd/settings.py</code></summary>

```python
DEBUG = False

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'shepherddb',
        'USER': 'shepherd',
        'PASSWORD': 'mypassword',
        'HOST': 'localhost',
        'PORT': '',
    }
}

# For Nginx proxy to Gunicorn
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
RATELIMIT_IP_META_KEY = 'HTTP_X_FORWARDED_FOR'
RATELIMIT_TRUSTED_PROXIES = ['127.0.0.1', '::1']
```

</details>

<details>
<summary><code>/etc/systemd/system/gunicorn.service</code></summary>

```ini
[Unit]
Description=gunicorn daemon
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/shepherd
Environment="PATH=/opt/shepherd/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/local/go/bin:/var/www/go/bin"
ExecStart=/bin/bash -c "source /var/www/.bashrc && /opt/shepherd/venv/bin/gunicorn --access-logfile - --workers 3 --bind unix:/opt/shepherd/gunicorn.sock shepherd.wsgi:application"

[Install]
WantedBy=multi-user.target
```

</details>

<details>
<summary><code>/etc/systemd/system/celery-beat.service</code></summary>

```ini
[Unit]
Description=Celery Beat Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/shepherd
Environment="PATH=/opt/shepherd/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/local/go/bin:/var/www/go/bin"
ExecStart=/bin/bash -c "source /var/www/.bashrc && /opt/shepherd/venv/bin/celery -A shepherd beat -l INFO --scheduler django_celery_beat.schedulers:DatabaseScheduler"

[Install]
WantedBy=multi-user.target
```

</details>

<details>
<summary><code>/etc/systemd/system/celery-worker.service</code></summary>

```ini
[Unit]
Description=Celery Worker Service
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/shepherd
Environment="PATH=/opt/shepherd/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/local/go/bin:/var/www/go/bin"
ExecStart=/bin/bash -c "source /var/www/.bashrc && /opt/shepherd/venv/bin/celery -A shepherd worker --loglevel=info"

[Install]
WantedBy=multi-user.target
```

</details>

### Enable Services

```bash
systemctl enable --now gunicorn
systemctl enable --now redis-server
systemctl enable --now celery-beat
systemctl enable --now celery-worker
```

### SSL & Nginx

```bash
# Generate self-signed cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/shepherd.key \
  -out /etc/ssl/certs/shepherd.crt
```

<details>
<summary><code>/etc/nginx/sites-available/shepherd</code></summary>

```nginx
server {
    listen 80;
    server_name your_domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name your_domain.com;

    ssl_certificate /etc/ssl/certs/shepherd.crt;
    ssl_certificate_key /etc/ssl/private/shepherd.key;

    # Increase upload size limit (for large supplier lists, etc.)
    client_max_body_size 5M;

    location = /favicon.ico { access_log off; log_not_found off; }
    location /static/ {
        root /opt/shepherd;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/opt/shepherd/gunicorn.sock;
    }
}
```

</details>

```bash
rm /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/shepherd /etc/nginx/sites-enabled
nginx -t && systemctl restart nginx
```

### Initialize Database

```bash
./clean_all.sh
```

---

## 📄 License

MIT
