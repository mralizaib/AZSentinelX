# AZ Sentinel X — Local Ubuntu + Nginx Deployment Requirements

## 1. Operating System

- **Ubuntu 22.04 LTS** (or 20.04 LTS) recommended

---

## 2. System Packages

Install via `apt`:

```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    nginx \
    libpango-1.0-0 libpangoft2-1.0-0 \
    libcairo2 libcairo-gobject2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    libgobject-introspection-1.0-0 \
    libharfbuzz0b \
    fontconfig \
    libfreetype6 \
    postgresql postgresql-contrib \
    build-essential \
    git \
    curl
```

> **Important:** The `libpango*`, `libcairo*`, and related libraries are required by **WeasyPrint** for PDF report generation. Without them, PDF export will be disabled (HTML/XLSX still work).

---

## 3. Python Version

- **Python 3.10+** (Python 3.11 or 3.12 recommended)

Verify:
```bash
python3 --version
```

---

## 4. Python Dependencies

Install all dependencies from `requirements.txt`:

```bash
cd /path/to/Beta-v18
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Full `requirements.txt`:
```
flask>=3.1.0
flask-login>=0.6.3
flask-sqlalchemy>=3.1.1
flask-apscheduler>=1.13.1
gunicorn>=23.0.0
openai>=1.77.0
psycopg2-binary>=2.9.10
requests>=2.32.3
sqlalchemy>=2.0.40
urllib3>=2.4.0
weasyprint>=60.2
werkzeug>=3.1.3
jinja2>=3.1.6
opensearch-py>=2.8.0
sendgrid>=6.12.0
email-validator>=2.2.0
openpyxl>=3.0.0
reportlab>=3.6.0
feedparser>=6.0.0
```

> **Note:** `feedparser` is required by the **Threat Intelligence** module. Without it, the Threat Intelligence tab will fail with an Internal Server Error.

---

## 5. Database Setup (PostgreSQL)

```bash
sudo -u postgres psql

CREATE USER sentinelx WITH PASSWORD 'your-strong-password';
CREATE DATABASE sentinelx OWNER sentinelx;
GRANT ALL PRIVILEGES ON DATABASE sentinelx TO sentinelx;
\q
```

Set the `DATABASE_URL` environment variable:
```bash
export DATABASE_URL="postgresql://sentinelx:your-strong-password@localhost/sentinelx"
```

> **Fallback:** If `DATABASE_URL` is not set, the application automatically uses a local SQLite file (`sentinel.db`) in the application directory. SQLite is suitable for development/testing only.

---

## 6. Environment Variables

Create a `.env` file or set these in your system/systemd service:

```bash
# Flask
SESSION_SECRET=your-very-long-random-secret-key-here

# Database
DATABASE_URL=postgresql://sentinelx:your-strong-password@localhost/sentinelx

# Wazuh API
WAZUH_API_URL=https://your-wazuh-server:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=your-wazuh-api-password
WAZUH_VERIFY_SSL=False

# OpenSearch
OPENSEARCH_URL=https://your-wazuh-server:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=your-opensearch-password
OPENSEARCH_VERIFY_SSL=False
OPENSEARCH_INDEX_PATTERN=wazuh-alerts-*

# AI Integration (choose one or more)
OPENAI_API_KEY=sk-...                    # For OpenAI GPT-4o
DEEPSEEK_API_KEY=...                     # For DeepSeek (optional)
OLLAMA_API_URL=http://localhost:11434    # For local Ollama (optional)
# AI_INTEGRATIONS_GEMINI_API_KEY=...    # For Gemini (Replit only)

# Email / SMTP Alerts
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=True
```

> **Tip:** Use `python-dotenv` or a systemd `EnvironmentFile` to load these safely in production.

---

## 7. Running with Gunicorn (Production)

```bash
cd /path/to/Beta-v18
source venv/bin/activate
gunicorn --bind 127.0.0.1:5000 --workers 1 --threads 4 --timeout 120 main:app
```

> **Note:** Use `--workers 1` because the application uses in-process background threads (alert worker, APScheduler). Multiple workers would result in duplicate background jobs.

---

## 8. Systemd Service

Create `/etc/systemd/system/sentinelx.service`:

```ini
[Unit]
Description=AZ Sentinel X - Security Alert Management
After=network.target postgresql.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/Beta-v18
EnvironmentFile=/path/to/Beta-v18/.env
ExecStart=/path/to/Beta-v18/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 1 \
    --threads 4 \
    --timeout 120 \
    --access-logfile /var/log/sentinelx/access.log \
    --error-logfile /var/log/sentinelx/error.log \
    main:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo mkdir -p /var/log/sentinelx
sudo chown www-data:www-data /var/log/sentinelx
sudo systemctl daemon-reload
sudo systemctl enable sentinelx
sudo systemctl start sentinelx
sudo systemctl status sentinelx
```

---

## 9. Nginx Configuration

Create `/etc/nginx/sites-available/sentinelx`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Redirect HTTP to HTTPS (recommended)
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    # SSL certificates (use Let's Encrypt or your own)
    ssl_certificate     /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Forward headers to Flask (required for ProxyFix middleware)
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Increase timeouts for report generation and AI analysis
    proxy_connect_timeout 120s;
    proxy_send_timeout    120s;
    proxy_read_timeout    120s;

    # Increase body size for file uploads/exports
    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:5000;
    }

    location /static/ {
        alias /path/to/Beta-v18/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/sentinelx /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## 10. Default Login

On first run, a default admin user is created automatically:

| Field    | Value       |
|----------|-------------|
| Username | `admin`     |
| Password | `admin123`  |

**Change this password immediately** after first login via the Users section.

---

## 11. Troubleshooting Common Issues

### Threat Intelligence tab shows "Internal Server Error" (most common)
- **Cause:** `feedparser` Python package not installed. The Threat Intelligence module uses it to parse RSS security feeds. If it is missing, the **entire Threat Intelligence section** fails with a 500 error — including the index page, not just feed fetching.
- **Fix:**
  ```bash
  pip install feedparser>=6.0.0
  ```
  Then restart the application. Verify with:
  ```bash
  python3 -c "import feedparser; print(feedparser.__version__)"
  ```

### Alert details page does not load
- **Cause:** Nginx not forwarding `X-Forwarded-Proto` header, causing Flask to redirect loops, or OpenSearch connection failure.
- **Fix:** Ensure `proxy_set_header X-Forwarded-Proto $scheme;` is in your Nginx config, and verify `OPENSEARCH_URL`, `OPENSEARCH_USER`, `OPENSEARCH_PASSWORD` are correct.

### PDF reports not generating
- **Cause:** `libpango` system library missing.
- **Fix:** `sudo apt install libpango-1.0-0 libpangoft2-1.0-0`

### AI analysis not working
- **Cause:** No AI API key configured.
- **Fix:** Set `OPENAI_API_KEY` (or configure Ollama locally at `OLLAMA_API_URL`).

### Duplicate scheduler jobs / high CPU
- **Cause:** Running more than 1 Gunicorn worker.
- **Fix:** Always use `--workers 1` for this application.

### Session not persisting after Nginx restart
- **Cause:** `SESSION_SECRET` is not set or changes on restart.
- **Fix:** Set a fixed, long random string for `SESSION_SECRET` in your `.env` file.
