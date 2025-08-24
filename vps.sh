#!/bin/bash

# Constants
CONFIG_DIR="/etc/data"
LOG_FILE="/root/log-install.txt"
SUPPORTED_OS=("debian:11" "debian:12" "ubuntu:20.04" "ubuntu:22.04" "ubuntu:24.04")
DOMAIN_FILE="$CONFIG_DIR/domain"
USERPANEL_FILE="$CONFIG_DIR/userpanel"
PASSPANEL_FILE="$CONFIG_DIR/passpanel"
MARZBAN_DIR="/opt/marzban"

# Colorized echo function
colorized_echo() {
    local color=$1
    local text=$2
    case $color in
        "red")    printf "\e[91m%s\e[0m\n" "$text";;
        "green")  printf "\e[92m%s\e[0m\n" "$text";;
        "yellow") printf "\e[93m%s\e[0m\n" "$text";;
        "blue")   printf "\e[94m%s\e[0m\n" "$text";;
        "magenta") printf "\e[95m%s\e[0m\n" "$text";;
        "cyan")   printf "\e[96m%s\e[0m\n" "$text";;
        *)        echo "$text";;
    esac
}

# Logging function
log() {
    local level=$1
    local message=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    colorized_echo "$level" "$message"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log red "Error: This script must be run as root."
        exit 1
    fi
}

# Check supported OS
check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_key="${ID}:${VERSION_ID}"
        for supported in "${SUPPORTED_OS[@]}"; do
            if [[ "$os_key" == "$supported" ]]; then
                # Configure SSH keep-alive settings
                sed -i '/^[[:space:]]*#*ClientAliveInterval[[:space:]]/s/.*/ClientAliveInterval 10/' /etc/ssh/sshd_config
                sed -i '/^[[:space:]]*#*ClientAliveCountMax[[:space:]]/s/.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config
                systemctl restart sshd
                return 0
            fi
        done
    fi
    log red "Error: This script only supports Debian 11/12 and Ubuntu 20.04/22.04/24.04."
    exit 1
}

# Validate domain
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log red "Error: Invalid domain format."
        return 1
    fi
    return 0
}

# Validate email
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log red "Error: Invalid email format."
        return 1
    fi
    return 0
}

# Validate userpanel
validate_userpanel() {
    local userpanel=$1
    if [[ ! "$userpanel" =~ ^[A-Za-z0-9]+$ ]]; then
        log red "Error: UsernamePanel must contain only letters and numbers."
        return 1
    elif [[ "$userpanel" =~ [Aa][Dd][Mm][Ii][Nn] ]]; then
        log red "Error: UsernamePanel cannot contain 'admin'."
        return 1
    fi
    return 0
}

# Install packages
install_packages() {
    log blue "Updating package lists..."
    apt-get update -y || { log red "Failed to update package lists."; exit 1; }
    
    log blue "Installing required packages..."
    apt-get install -y sudo curl || { log red "Failed to install sudo and curl."; exit 1; }
    
    log blue "Removing unused packages..."
    apt-get -y --purge remove samba* apache2* sendmail* bind9* || log yellow "Note: Some packages couldn't be removed or weren't installed."
    
    log blue "Installing toolkit packages..."
    apt-get install -y libio-socket-inet6-perl libsocket6-perl libcrypt-ssleay-perl \
        libnet-libidn-perl libio-socket-ssl-perl libwww-perl libpcre3 libpcre3-dev \
        zlib1g-dev dbus iftop zip unzip wget net-tools curl nano sed screen gnupg \
        gnupg1 bc apt-transport-https build-essential dirmngr dnsutils sudo at htop vnstat \
        iptables bsdmainutils cron lsof lnav || { log red "Failed to install toolkit packages."; exit 1; }
    
    # Install speedtest
    log blue "Installing speedtest..."
    wget -q https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz || { log red "Failed to download speedtest."; exit 1; }
    tar xzf ookla-speedtest-1.2.0-linux-x86_64.tgz > /dev/null 2>&1 || { log red "Failed to extract speedtest."; exit 1; }
    mv speedtest /usr/bin || { log red "Failed to install speedtest."; exit 1; }
    rm -f ookla-speedtest-1.2.0-linux-x86_64.tgz speedtest.* > /dev/null 2>&1
}

# Main installation
main() {
    clear
    check_root
    check_os
    
    mkdir -p "$CONFIG_DIR"
    touch "$LOG_FILE"
    
    # Get user inputs
    while true; do
        read -rp "Enter Domain: " domain
        validate_domain "$domain" && break
    done
    echo "$domain" > "$DOMAIN_FILE"
    
    while true; do
        read -rp "Enter your Email: " email
        validate_email "$email" && break
    done
    
    while true; do
        read -rp "Enter UsernamePanel (letters and numbers only): " userpanel
        validate_userpanel "$userpanel" && break
    done
    echo "$userpanel" > "$USERPANEL_FILE"
    
    read -rp "Enter Password Panel: " passpanel
    echo "$passpanel" > "$PASSPANEL_FILE"
    
    # Preparation
    clear
    cd
    
    install_packages
    configure_bbr
    
    # Set timezone
    log blue "Setting timezone to Asia/Jakarta..."
    timedatectl set-timezone Asia/Jakarta || { log red "Failed to set timezone."; exit 1; }
    
    # Install Marzban
    log blue "Installing Marzban..."
    bash -c "$(curl -sL https://raw.githubusercontent.com/wibusantun/Marzvps/main/install)" @ install
    
    # Install subscriptions and environment
    log blue "Configuring Marzban components..."
    wget -q -N -P /var/lib/marzban/templates/subscription/ https://raw.githubusercontent.com/wibusantun/Marzvps/main/index.html

    # Create custom .env file
    cat > "$MARZBAN_DIR/.env" << 'EOF'
UVICORN_HOST = "0.0.0.0"
UVICORN_PORT = 7879

## We highly recommend add admin using `marzban cli` tool and do not use
## the following variables which is somehow hard codded infrmation.
# SUDO_USERNAME = "admin"
# SUDO_PASSWORD = "admin"

# UVICORN_UDS: "/run/marzban.socket"
# UVICORN_SSL_CERTFILE = "/var/lib/marzban/certs/fullchain.pem"
# UVICORN_SSL_KEYFILE = "/var/lib/marzban/certs/key.pem"

XRAY_JSON = "/var/lib/marzban/xray_config.json"
# XRAY_EXECUTABLE_PATH = "/var/lib/marzban/core/xray"
# XRAY_SUBSCRIPTION_URL_PREFIX = "https://example.com"
# XRAY_EXECUTABLE_PATH = "/var/lib/marzban/core/xray"
XRAY_ASSETS_PATH = "/var/lib/marzban/assets"
# XRAY_FALLBACKS_INBOUND_TAG = "INBOUND_X"

# TELEGRAM_API_TOKEN = 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# TELEGRAM_ADMIN_ID = 987654321
# TELEGRAM_PROXY_URL = "http://localhost:8080"

# CLASH_SUBSCRIPTION_TEMPLATE="clash/my-custom-template.yml"
SUBSCRIPTION_PAGE_TEMPLATE="subscription/index.html"
CUSTOM_TEMPLATES_DIRECTORY="/var/lib/marzban/templates/"
HOME_PAGE_TEMPLATE="home/index.html"
# SUBBSCRIPTION_PAGE_LANG="en"

SQLALCHEMY_DATABASE_URL = "sqlite:////var/lib/marzban/db.sqlite3"

### for developers
DOCS=true
# DEBUG=true
# WEBHOOK_ADDRESS = "http://127.0.0.1:9000/"
# WEBHOOK_SECRET = "something-very-very-secret"
# VITE_BASE_API="https://example.com/api/"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 0
EOF
    mkdir -p /var/lib/marzban/assets

    # Install docker-compose
    cat > "$MARZBAN_DIR/docker-compose.yml" << 'EOF'
services:
  marzban:
    image: gozargah/marzban:latest
    restart: always
    env_file: .env
    network_mode: host
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    volumes:
    - /etc/timezone:/etc/timezone:ro
    - /etc/localtime:/etc/localtime:ro
    - /var/lib/marzban:/var/lib/marzban

  nginx:
    image: nginx
    restart: always
    network_mode: host
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    volumes:
    - /var/lib/marzban:/var/lib/marzban
    - /var/www/html:/var/www/html
    - /etc/timezone:/etc/timezone:ro
    - /etc/localtime:/etc/localtime:ro
    - /var/log/nginx/access.log:/var/log/nginx/access.log
    - /var/log/nginx/error.log:/var/log/nginx/error.log
    - ./nginx.conf:/etc/nginx/nginx.conf
    - ./default.conf:/etc/nginx/conf.d/default.conf
    - ./xray.conf:/etc/nginx/conf.d/xray.conf
EOF

    # Install nginx
    log blue "Installing nginx..."
    mkdir -p /var/log/nginx /var/www/html
    touch /var/log/nginx/access.log /var/log/nginx/error.log
        
    # Create nginx.conf
    cat > "$MARZBAN_DIR/nginx.conf" << 'EOF'
user  www-data;
worker_processes 3;

error_log /dev/null;
error_log off;
events {
    worker_connections 4096;
    multi_accept off;
    use epoll;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /dev/null;
    access_log off;

    sendfile       on;
    tcp_nopush     on;
    tcp_nodelay    on;
    keepalive_timeout 65;
    keepalive_requests 10000;
    types_hash_max_size 2048;
    gzip off;

    include conf.d/*.conf;
}
EOF
    
    # Create default.conf
    cat > "$MARZBAN_DIR/default.conf" << 'EOF'
server {
  listen       8081;
  server_name  127.0.0.1 localhost;

  access_log /dev/null;
  access_log off;
  error_log  /dev/null;
  error_log off;
 
  root   /var/www/html;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \.php$ {
    include fastcgi_params;
    fastcgi_pass  127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}
EOF
    
    # Create xray.conf
    cat > "$MARZBAN_DIR/xray.conf" << 'EOF'
server {
    listen 80;
    listen [::]:80;
    listen [::]:443 ssl ipv6only=off reuseport;
    listen [::]:443 quic reuseport ipv6only=off;
    http2 on;
    # Real IP - IPv4
    set_real_ip_from 127.0.0.0/24;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    # Real IP - IPv6
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    # SSL
    server_name 127.0.0.1 localhost;
    real_ip_header X-Forwarded-For;
    ssl_certificate /var/lib/marzban/xray.crt;
    ssl_certificate_key /var/lib/marzban/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    
    root /var/www/html;

    # Dashboard / API
    location ~* ^/(dashboard|statics|api|docs|sub|redoc|openapi.json) {
        proxy_pass http://127.0.0.1:7879;
        proxy_http_version 1.1;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    # Trojan WS
    location /trojan {
        if ($http_upgrade != "upgrade") {
            rewrite /(.*) /trojan break;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    # Vmess WS
    location /vmess {
        if ($http_upgrade != "upgrade") {
            rewrite /(.*) /vmess break;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:3002;
        proxy_http_version 1.1;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    # Vless WS
    location /vless {
        if ($http_upgrade != "upgrade") {
            rewrite /(.*) /vless break;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:3003;
        proxy_http_version 1.1;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    # Up Trojan WS
    location /uptrojan {
        if ($http_upgrade != "websocket") {
            rewrite /(.*) /uptrojan break;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:4001;
        proxy_http_version 1.1;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    # Up Vmess WS
    location /upvmess {
        if ($http_upgrade != "websocket") {
            rewrite /(.*) /upvmess break;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:4002;
        proxy_http_version 1.1;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    # Up Vless WS
    location /upvless {
        if ($http_upgrade != "websocket") {
            rewrite /(.*) /upvless break;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:4003;
        proxy_http_version 1.1;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

    # Install socat
    log blue "Installing socat and related packages..."
    apt install -y iptables curl socat xz-utils apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release cron bash-completion || { log red "Failed to install socat packages."; exit 1; }
    
    # Install certificates
    log blue "Installing acme.sh..."
    curl -s https://get.acme.sh | sh -s email="$email" || { log red "Failed to install acme.sh."; exit 1; }

    log blue "Issuing SSL certificate for $domain..."
    ~/.acme.sh/acme.sh --issue --force --standalone --server letsencrypt -k ec-256 -d "$domain" || { log red "Failed to issue SSL certificate."; exit 1; }

    log blue "Installing SSL certificate..."
    ~/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchain-file /var/lib/marzban/xray.crt \
        --key-file /var/lib/marzban/xray.key \
        --ecc || { log red "Failed to install SSL certificate."; exit 1; }

    log green "SSL certificate installation completed successfully."
    
    # Create xray_config.json
    log blue "Creating xray_config.json..."
    cat > /var/lib/marzban/xray_config.json << 'EOF'
{
  "log": {
    "loglevel": "none"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "8.8.8.8",
      "127.0.0.1",
      "localhost"
    ],
    "disableCache": true,
    "tag": "dns-in"
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "domainMatcher": "hybrid",
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "dns-in"
        ],
        "outboundTag": "dns-out"
      },
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "ip": [
          "geoip:id"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "domain": [
          "geosite:category-porn",
          "geosite:category-games",
          "geosite:akamai",
          "geosite:microsoft",
          "geosite:fastly",
          "geosite:google",
          "geosite:discord",
          "geosite:facebook",
          "geosite:instagram",
          "geosite:telegram",
          "geosite:tiktok",
          "geosite:twitter",
          "geosite:whatsapp",
          "geosite:youtube",
          "geosite:zoom",
          "bca.co.id",
          "bankmandiri.co.id",
          "bni.co.id",
          "bri.co.id",
          "brimo.bri.co.id",
          "klikbca.com",
          "livin.bmri.id",
          "m.klikbca.com",
          "wondr.bni.co.id",
          "blibli.com",
          "bukalapak.com",
          "lazada.co.id",
          "shopee.co.id",
          "tokopedia.com",
          "gojek.com",
          "grab.com",
          "myim3.indosatooredoo.com",
          "smartfren.com",
          "telkomsel.com",
          "tsel.me",
          "xl.co.id"
        ],
        "network": "tcp,udp",
        "outboundTag": "direct"
      }
    ]
  },
  "inbounds": [
    {
      "tag": "TROJAN_WS",
      "listen": "127.0.0.1",
      "port": 3001,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/trojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    },
    {
      "tag": "VMESS_WS",
      "listen": "127.0.0.1",
      "port": 3002,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    },
    {
      "tag": "VLESS_WS",
      "listen": "127.0.0.1",
      "port": 3003,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vless"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    },
    {
      "tag": "TROJAN_UPGRADE",
      "listen": "127.0.0.1",
      "port": 4001,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": {
          "path": "/uptrojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    },
    {
      "tag": "VMESS_UPGRADE",
      "listen": "127.0.0.1",
      "port": 4002,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": {
          "path": "/upvmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    },
    {
      "tag": "VLESS_UPGRADE",
      "listen": "127.0.0.1",
      "port": 4003,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": {
          "path": "/upvless"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      }
    },
    {
      "tag": "dns-out",
      "protocol": "dns",
      "settings": {
        "nonIPQuery": "skip"
      }
    }
  ]
}
EOF
    
    # Finalize Marzban setup
    log blue "Finalizing Marzban setup..."
    cd "$MARZBAN_DIR"
    sed -i "s/# SUDO_USERNAME = \"admin\"/SUDO_USERNAME = \"${userpanel}\"/" .env
    sed -i "s/# SUDO_PASSWORD = \"admin\"/SUDO_PASSWORD = \"${passpanel}\"/" .env
    docker compose down && docker compose up -d || { log red "Failed to start Marzban services."; exit 1; }
    marzban cli admin import-from-env -y || { log red "Failed to import admin from env."; exit 1; }
    sed -i "s/SUDO_USERNAME = \"${userpanel}\"/# SUDO_USERNAME = \"admin\"/" .env
    sed -i "s/SUDO_PASSWORD = \"${passpanel}\"/# SUDO_PASSWORD = \"admin\"/" .env
    docker compose down && docker compose up -d || { log red "Failed to restart Marzban services."; exit 1; }
    
    # Generate API token
    get_token() {
    log blue "Generating API token..."
    sleep 20

    token_json=$(curl -sf -X POST "https://${domain}/api/admin/token" \
        -H 'accept: application/json' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "grant_type=password&username=${userpanel}&password=${passpanel}&scope=&client_id=string&client_secret=string") \
        || { log red "Failed to generate API token."; return 1; }

    echo "$token_json" > /etc/data/token.json

    access_token=$(echo "$token_json" | jq -r '.access_token')

    if [[ -z "$access_token" || "$access_token" == "null" ]]; then
        log red "Failed to parse access token."
        return 1
    fi

    log green "API token generated successfully!"
    export access_token
}
    
    # Clean up
    log blue "Cleaning up..."
    apt autoremove -y
    
    # Log installation details
    cat <<EOF > "$LOG_FILE"
Marzban Dashboard Login Details:
==================================
URL: https://${domain}/dashboard
Username: ${userpanel}
Password: ${passpanel}
==================================
EOF
    cat "$LOG_FILE"
    
    log green "Script successfully installed."
    
    # Prompt for reboot
    read -rp "Reboot to apply changes? [default y] (y/n): " answer
    if [[ "$answer" != "n" && "$answer" != "N" ]]; then
        log blue "Rebooting system..."
        cat /dev/null > ~/.bash_history && history -c
        reboot
    fi
}

# Trap errors
trap 'log red "Script terminated due to an error."; exit 1' ERR

# Execute main
main "$@"