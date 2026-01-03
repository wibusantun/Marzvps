#!/bin/bash
set -e
set -o pipefail
# === Constants ===
CONFIG_DIR="/etc/data"
MARZBAN_DIR="/opt/marzban"
LOG_FILE="/root/log-install.txt"
DOMAIN_FILE="$CONFIG_DIR/domain"
USERPANEL_FILE="$CONFIG_DIR/userpanel"
PASSPANEL_FILE="$CONFIG_DIR/passpanel"
SUPPORTED_OS=("debian:10" "debian:11" "debian:12" "ubuntu:20.04" "ubuntu:22.04" "ubuntu:24.04")

# === Colorized Echo ===
colorized_echo() {
    local color=$1
    local text=$2
    case $color in
        "red")     printf "\e[91m%s\e[0m\n" "$text";;
        "green")   printf "\e[92m%s\e[0m\n" "$text";;
        "yellow")  printf "\e[93m%s\e[0m\n" "$text";;
        "blue")    printf "\e[94m%s\e[0m\n" "$text";;
        "magenta") printf "\e[95m%s\e[0m\n" "$text";;
        "cyan")    printf "\e[96m%s\e[0m\n" "$text";;
        *)         echo "$text";;
    esac
}

# === Logger ===
log() {
    local level=$1
    local message=$2

    case "$level" in
        info) color="green" ;;
        warning) color="yellow" ;;
        error) color="red" ;;
        debug) color="cyan" ;;
        blue|green|yellow|red|magenta|cyan) color="$level" ;;
        *) color="white" ;;
    esac

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    colorized_echo "$color" "$message"
}

# === Root Check ===
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log red "Error: This script must be run as root."
        exit 1
    fi
}

# === OS Check & SSH Keep-Alive ===
check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_key="${ID}:${VERSION_ID}"
        for supported in "${SUPPORTED_OS[@]}"; do
            if [[ "$os_key" == "$supported" ]]; then
                sed -i '/^[[:space:]]*#*ClientAliveInterval[[:space:]]/s/.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
                sed -i '/^[[:space:]]*#*ClientAliveCountMax[[:space:]]/s/.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
                if sshd -t 2>/dev/null; then
                    if systemctl list-units --type=service | grep -q 'sshd.service'; then
                        systemctl restart sshd
                        log green "SSH service 'sshd' restarted safely."
                    elif systemctl list-units --type=service | grep -q 'ssh.service'; then
                        systemctl restart ssh
                        log green "SSH service 'ssh' restarted safely."
                    else
                        log yellow "Warning: SSH service not found. Manual restart may be required."
                    fi
                else
                    log red "Error: SSH config test failed! Restart aborted to avoid lockout."
                fi
                return 0
            fi
        done
    fi
    log red "Error: This script only supports Debian 10/11/12 and Ubuntu 20.04/22.04/24.04."
    exit 1
}

# === Validation: Domain ===
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log red "Error: Invalid domain format."
        return 1
    fi
    return 0
}

# === Validation: Email ===
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log red "Error: Invalid email format."
        return 1
    fi
    return 0
}

# === Validation: Username Panel ===
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

# === Install Packages (Base + Speedtest) ===
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
        iptables bsdmainutils cron lsof lnav jq sqlite3 libsqlite3-dev \
        || { log red "Failed to install toolkit packages."; exit 1; }

    # === Install speedtest ===
    log blue "Installing speedtest..."
    wget -q https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz || { log red "Failed to download speedtest."; exit 1; }
    tar xzf ookla-speedtest-1.2.0-linux-x86_64.tgz > /dev/null 2>&1 || { log red "Failed to extract speedtest."; exit 1; }
    mv speedtest /usr/bin || { log red "Failed to install speedtest."; exit 1; }
    rm -f ookla-speedtest-1.2.0-linux-x86_64.tgz speedtest.* > /dev/null 2>&1
}

# === Network Tuning (BBR & Sysctl) ===
configure_network_bbr() {

    modprobe tcp_bbr 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr

    MODULES_FILE="/etc/modules-load.d/bbr.conf"
    if [ ! -f "$MODULES_FILE" ]; then
        echo "tcp_bbr" > "$MODULES_FILE"
    elif ! grep -q "tcp_bbr" "$MODULES_FILE"; then
        echo "tcp_bbr" >> "$MODULES_FILE"
    fi

    SYSCTL_SETTINGS=(
        "kernel.panic=10"
        "kernel.panic_on_oops=1"
        "vm.swappiness=10"
        "vm.vfs_cache_pressure=50"
        "vm.dirty_ratio=30"
        "vm.dirty_background_ratio=10"
        "net.core.default_qdisc=fq"
        "net.core.netdev_max_backlog=2500"
        "net.core.somaxconn=4096"
        "net.core.rmem_default=212992"
        "net.core.wmem_default=212992"
        "net.core.rmem_max=212992"
        "net.core.wmem_max=212992"
		"net.core.optmem_max=20480"
        "net.ipv4.tcp_congestion_control=bbr"
        "net.ipv4.tcp_fastopen=3"
        "net.ipv4.tcp_ecn=1"
        "net.ipv4.tcp_ecn_fallback=0"
        "net.ipv4.tcp_fin_timeout=25"
        "net.ipv4.tcp_keepalive_time=600"
        "net.ipv4.tcp_keepalive_intvl=30"
        "net.ipv4.tcp_keepalive_probes=7"
        "net.ipv4.tcp_sack=1"
        "net.ipv4.tcp_dsack=1"
		"net.ipv4.tcp_fack=1"
		"net.ipv4.tcp_tw_reuse=1"
        "net.ipv4.tcp_syncookies=1"
        "net.ipv4.tcp_syn_retries=2"
        "net.ipv4.tcp_synack_retries=2"
        "net.ipv4.tcp_retries2=8"
        "net.ipv4.tcp_no_metrics_save=1"
		"net.ipv4.tcp_mtu_probing=1"
        "net.ipv4.tcp_slow_start_after_idle=0"
		"net.ipv4.tcp_moderate_rcvbuf=1"
        "net.ipv4.tcp_window_scaling=1"
		"net.ipv4.tcp_max_orphans=8192"
        "net.ipv4.tcp_max_syn_backlog=1024"
		"net.ipv4.tcp_mem=22350 29802 44700"
        "net.ipv4.tcp_rmem=4096 32768 1048576"
        "net.ipv4.tcp_wmem=4096 16384 1048576"
		"net.ipv4.udp_mem=44703 59605 89406"
        "net.ipv4.udp_rmem_min=4096"
        "net.ipv4.udp_wmem_min=4096"
        "net.ipv4.ip_forward=1"
        "net.ipv4.ip_local_port_range=1024 65535"
		"net.ipv6.conf.all.disable_ipv6=1"
		"net.ipv6.conf.default.disable_ipv6=1"
    )

    for s in "${SYSCTL_SETTINGS[@]}"; do
        key="$(echo "${s%%=*}" | xargs)"
        value="$(echo "${s#*=}" | xargs)"

        if grep -qE "^${key}[[:space:]]*=" /etc/sysctl.conf; then
            sed -i "s|^${key}[[:space:]]*=.*|${key} = ${value}|" /etc/sysctl.conf
        else
            echo "${key} = ${value}" >> /etc/sysctl.conf
        fi

        sysctl -w "${key}=${value}" >/dev/null 2>&1
    done

    sysctl -p >/dev/null 2>&1

    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo "[OK] BBR enabled and persistent."
    else
        echo "[ERROR] Failed to enable BBR."
    fi
}

# === Main ===
main() {
    clear
    check_root
    check_os
    mkdir -p "$CONFIG_DIR"
    touch "$LOG_FILE"

    # === Inputs ===
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

    # === Preparation ===
    clear
    cd || exit 1
    install_packages
    configure_network_bbr
    # === Timezone ===
    log blue "Setting timezone to Asia/Jakarta..."
    timedatectl set-timezone Asia/Jakarta || { log red "Failed to set timezone."; exit 1; }

    # === Install Marzban ===
    log blue "Installing Marzban..."
    bash -c "$(curl -sL https://raw.githubusercontent.com/wibusantun/Marzvps/main/marzban.sh)" @ install

    # === Configure Marzban Subs & Env ===
    log blue "Configuring Marzban components..."
    wget -q -N -P /var/lib/marzban/templates/subscription/ https://raw.githubusercontent.com/wibusantun/Marzvps/main/index.html
    
    cd "$MARZBAN_DIR" || exit 1
    # .env
    cat > "$MARZBAN_DIR/.env" << 'EOF'
UVICORN_HOST=0.0.0.0
UVICORN_PORT=8000
# ALLOWED_ORIGINS=http://localhost,http://localhost:8000,http://example.com

## We highly recommend add admin using `marzban cli` tool and do not use
## the following variables which is somehow hard coded information.
# SUDO_USERNAME=admin
# SUDO_PASSWORD=admin

# UVICORN_UDS=/run/marzban.socket
UVICORN_SSL_CERTFILE=/var/lib/marzban/fullchain.pem
UVICORN_SSL_KEYFILE=/var/lib/marzban/key.pem
# UVICORN_SSL_CA_TYPE=public

# DASHBOARD_PATH=/dashboard/

XRAY_JSON=/var/lib/marzban/xray_config.json
# XRAY_SUBSCRIPTION_URL_PREFIX=https://example.com
# XRAY_SUBSCRIPTION_PATH=sub
XRAY_EXECUTABLE_PATH=/var/lib/marzban/xray-core/xray
XRAY_ASSETS_PATH=/var/lib/marzban/xray-core/
# XRAY_EXCLUDE_INBOUND_TAGS=INBOUND_X INBOUND_Y
# XRAY_FALLBACKS_INBOUND_TAG=INBOUND_X


# TELEGRAM_API_TOKEN=123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# TELEGRAM_ADMIN_ID=987654321,123456789
# TELEGRAM_LOGGER_CHANNEL_ID=-1234567890123
# TELEGRAM_DEFAULT_VLESS_FLOW=xtls-rprx-vision
# TELEGRAM_PROXY_URL=http://localhost:8080

# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxxxxxx

CUSTOM_TEMPLATES_DIRECTORY=/var/lib/marzban/templates/
# CLASH_SUBSCRIPTION_TEMPLATE=clash/my-custom-template.yml
SUBSCRIPTION_PAGE_TEMPLATE=/subscription/index.html
HOME_PAGE_TEMPLATE=home/index.html

# V2RAY_SUBSCRIPTION_TEMPLATE=v2ray/default.json
# V2RAY_SETTINGS_TEMPLATE=v2ray/settings.json

# SINGBOX_SUBSCRIPTION_TEMPLATE=singbox/default.json
# SINGBOX_SETTINGS_TEMPLATE=singbox/settings.json

# MUX_TEMPLATE=mux/default.json

## Enable JSON config for compatible clients to use mux, fragment, etc. Default False.
# USE_CUSTOM_JSON_DEFAULT=True
## Your preferred config type for different clients
## If USE_CUSTOM_JSON_DEFAULT is set True, all following programs will use the JSON config
# USE_CUSTOM_JSON_FOR_V2RAYN=False
# USE_CUSTOM_JSON_FOR_V2RAYNG=True
# USE_CUSTOM_JSON_FOR_STREISAND=False
# USE_CUSTOM_JSON_FOR_HAPP=False

## Set headers for subscription
# SUB_PROFILE_TITLE=Subscription
# SUB_SUPPORT_URL=https://t.me/support
# SUB_UPDATE_INTERVAL=12

## External config to import into v2ray format subscription
# EXTERNAL_CONFIG=config://...

SQLALCHEMY_DATABASE_URL=sqlite:////var/lib/marzban/db.sqlite3?timeout=30&journal_mode=WAL&synchronous=NORMAL
# SQLALCHEMY_POOL_SIZE=10
# SQLALCHEMY_MAX_OVERFLOW=30

## Custom text for STATUS_TEXT variable
# ACTIVE_STATUS_TEXT=Active
# EXPIRED_STATUS_TEXT=Expired
# LIMITED_STATUS_TEXT=Limited
# DISABLED_STATUS_TEXT=Disabled
# ONHOLD_STATUS_TEXT=On-Hold

### Use negative values to disable auto-delete by default
# USERS_AUTODELETE_DAYS=-1
# USER_AUTODELETE_INCLUDE_LIMITED_ACCOUNTS=false

## Customize all notifications
# NOTIFY_STATUS_CHANGE=True
# NOTIFY_USER_CREATED=True
# NOTIFY_USER_UPDATED=True
# NOTIFY_USER_DELETED=True
# NOTIFY_USER_DATA_USED_RESET=True
# NOTIFY_USER_SUB_REVOKED=True
# NOTIFY_IF_DATA_USAGE_PERCENT_REACHED=True
# NOTIFY_IF_DAYS_LEFT_REACHED=True
# NOTIFY_LOGIN=True

## Whitelist of IPs/hosts to disable login notifications
# LOGIN_NOTIFY_WHITE_LIST=1.1.1.1,127.0.0.1

### for developers
# DOCS=True
# DEBUG=True

# If You Want To Send Webhook To Multiple Server Add Multi Address
# WEBHOOK_ADDRESS=http://127.0.0.1:9000/,http://127.0.0.1:9001/
# WEBHOOK_SECRET=something-very-very-secret
# NOTIFY_DAYS_LEFT=3,7
# NOTIFY_REACHED_USAGE_PERCENT=80,90

# VITE_BASE_API=https://example.com/api/
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=0

# JOB_CORE_HEALTH_CHECK_INTERVAL=10
# JOB_RECORD_NODE_USAGES_INTERVAL=30
# JOB_RECORD_USER_USAGES_INTERVAL=10
# JOB_REVIEW_USERS_INTERVAL=10
# JOB_SEND_NOTIFICATIONS_INTERVAL=30
EOF

    # === Install Xray-Core ===
    mkdir -p /var/lib/marzban/xray-core
    cd /var/lib/marzban/xray-core
    wget -O xray.zip "https://raw.githubusercontent.com/wibusantun/Marzvps/main/Xray-linux-64.zip"
    unzip -o xray.zip
    chmod +x xray
    rm -f xray.zip
    chmod -R 755 /var/lib/marzban/xray-core

    # docker-compose.yml
    cat > "$MARZBAN_DIR/docker-compose.yml" << 'EOF'
services:
  marzban:
    image: gozargah/marzban:latest
    container_name: marzban
    restart: always
    env_file: .env
    network_mode: host
    volumes:
      - /var/lib/marzban:/var/lib/marzban
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    environment:
      - XRAY_EXECUTABLE_PATH=/var/lib/marzban/xray-core/xray
      - XRAY_ASSETS_PATH=/var/lib/marzban/xray-core
      - CUSTOM_TEMPLATES_DIRECTORY=/var/lib/marzban/templates
      - SUBSCRIPTION_PAGE_TEMPLATE=/subscription/index.html

  nginx:
    image: nginx:latest
    container_name: nginx
    restart: always
    network_mode: host
    volumes:
      - /var/lib/marzban:/var/lib/marzban
      - /var/www/html:/var/www/html
      - /var/log/nginx/access.log:/var/log/nginx/access.log
      - /var/log/nginx/error.log:/var/log/nginx/error.log
      - ./default.conf:/etc/nginx/conf.d/default.conf
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./xray.conf:/etc/nginx/conf.d/xray.conf
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
EOF

    # === Install Nginx ===
    log blue "Installing nginx..."
    mkdir -p /var/www/html
    cat <<'EOF' > /var/www/html/index.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Welcome to Nginx</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#f4f4f9;color:#333;text-align:center;padding:50px}
h1{font-size:3em;color:#2e6f95;margin-bottom:20px}
p{font-size:1.2em;color:#555;line-height:1.6;margin-bottom:20px}
a{text-decoration:none;color:#fff;font-weight:bold}
.container{background:#fff;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,.1);padding:40px;max-width:800px;margin:auto}
.footer{margin:30px 0 20px;color:#999}
.footer a{color:#2e6f95;font-weight:bold}
.button{background:#2e6f95;color:#fff;padding:15px 30px;font-size:1.1em;border:0;border-radius:5px;cursor:pointer;display:inline-block;margin-top:20px}
.button:hover{background:#1a4d6d}
@media (prefers-color-scheme:dark){
body{background:#121212;color:#e0e0e0}
.container{background:#1e1e1e;box-shadow:0 4px 12px rgba(0,0,0,.6)}
h1{color:#6fb3d2}
p{color:#ccc}
.footer{color:#777}
.footer a{color:#6fb3d2}
.button{background:#3a7ca5}
.button:hover{background:#2a5d7c}
}
@media (max-width:600px){
h1{font-size:2.5em}
p{font-size:1em}
}
</style>
</head>
<body>
<div class="container">
<h1>Welcome to Nginx!</h1>
<p>If you're seeing this page, it means Nginx is successfully installed and running on your server. You can now configure Nginx to serve your web applications or other services.</p>
<p>For further configuration and documentation, please refer to <a href="http://nginx.org/" target="_blank">nginx.org</a>.</p>
</div>
<div class="footer">
<p>Powered by <a href="https://nginx.org/" target="_blank">Nginx</a></p>
</div>
</body>
</html>
EOF
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    mkdir -p /var/log/nginx
    touch /var/log/nginx/access.log /var/log/nginx/error.log

    # default.conf
    cat > "$MARZBAN_DIR/default.conf" << 'EOF'
server {
    listen 8010;
    server_name _;
    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location ~ /\. {
        deny all;
    }
}
EOF

    # nginx.conf
    cat > "$MARZBAN_DIR/nginx.conf" << 'EOF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
}

http {
    include mime.types;
    default_type application/octet-stream;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    keepalive_timeout 65;
    types_hash_max_size 2048;
    log_not_found off;
    gzip off;

    access_log off;
    error_log /dev/null;

    include /etc/nginx/conf.d/*.conf;
}
EOF

    # xray.conf
    cat > "$MARZBAN_DIR/xray.conf" << 'EOF'
map $uri $websocket_backend {
    default "";
    ~^/trojan    http://127.0.0.1:3001;
    ~^/vmess     http://127.0.0.1:3002;
    ~^/vless     http://127.0.0.1:3003;
    ~^/uptrojan  http://127.0.0.1:3004;
    ~^/upvmess   http://127.0.0.1:3005;
    ~^/upvless   http://127.0.0.1:3006;
}

map $uri $grpc_backend {
    default "";
    ~^/grpc-trojan grpc://127.0.0.1:3007;
    ~^/grpc-vmess  grpc://127.0.0.1:3008;
    ~^/grpc-vless  grpc://127.0.0.1:3009;
}

server {
    listen 80 reuseport;
    listen [::]:80 reuseport;
    listen 2052 reuseport;
    listen 2082 reuseport;
    listen 2086 reuseport;
    listen 2095 reuseport;
    listen 8080 reuseport;
    listen 8880 reuseport;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl reuseport;
    listen [::]:443 ssl reuseport;
    listen 2053 ssl reuseport;
    listen 2083 ssl reuseport;
    listen 2087 ssl reuseport;
    listen 2096 ssl reuseport;
    listen 8443 ssl reuseport;
    http2 on;

    server_name 127.0.0.1 localhost;

    ssl_certificate     /var/lib/marzban/fullchain.pem;
    ssl_certificate_key /var/lib/marzban/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:HIGH:!aNULL:!MD5:!RC4:!3DES';
    ssl_session_tickets off;

    real_ip_header CF-Connecting-IP;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;

    location ~ ^/(dashboard|statics|api|docs|sub|redoc|openapi\.json)(/|$) {
        proxy_pass https://127.0.0.1:8000;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location ~ ^/grpc-(trojan|vmess|vless) {
        if ($content_type !~ "^application/grpc") { return 404; }
        client_max_body_size 0;
        grpc_pass $grpc_backend;
        grpc_socket_keepalive on;
        grpc_set_header Host $host;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location ~ ^/(trojan|vmess|vless|uptrojan|upvmess|upvless) {
        proxy_pass $websocket_backend;
        proxy_http_version 1.1;
        proxy_redirect off;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://127.0.0.1:8010;
        proxy_set_header Host $host;
    }
}
EOF
    # === Auto Input server_name ===
    sed -i "s/server_name 127.0.0.1 localhost;/server_name $domain *.$domain;/" "$MARZBAN_DIR/xray.conf"

    # === Socat & ACME (Certificates) ===
    log blue "Installing socat and related packages..."
    apt install -y iptables curl socat xz-utils apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release cron bash-completion || { log red "Failed to install socat packages."; exit 1; }

    log blue "Setting ownership and permissions for /var/lib/marzban..."
    chown root:root /var/lib/marzban || { log red "Failed to set ownership for /var/lib/marzban."; exit 1; }
    chmod 755 /var/lib/marzban || { log red "Failed to set permissions for /var/lib/marzban."; exit 1; }

    log blue "Installing acme.sh..."
    curl -s https://get.acme.sh | sh -s email="$email" || { log red "Failed to install acme.sh."; exit 1; }

    log blue "Issuing SSL certificate for $domain..."
    ~/.acme.sh/acme.sh --issue --force --standalone --server letsencrypt -k ec-256 -d "$domain" || { log red "Failed to issue SSL certificate."; exit 1; }

    log blue "Installing SSL certificate..."
    ~/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchain-file /var/lib/marzban/fullchain.pem \
        --key-file /var/lib/marzban/key.pem \
        --ecc || { log red "Failed to install SSL certificate."; exit 1; }

    log blue "Setting permissions for SSL certificate files..."
    chmod 600 /var/lib/marzban/key.pem || { log red "Failed to set permissions for key.pem."; exit 1; }
    chmod 644 /var/lib/marzban/fullchain.pem || { log red "Failed to set permissions for fullchain.pem."; exit 1; }

    log green "SSL certificate installation completed successfully."

    # === XRAY Config ===
    log blue "Creating xray_config.json..."
    cat > /var/lib/marzban/xray_config.json << 'EOF'
{
  "log": {
    "loglevel": "none"
  },
  "dns": {
    "hosts": {},
    "servers": [
      "1.1.1.1",
      "8.8.8.8",
      "localhost"
    ],
    "port": 53,
    "strategy": "UseIP",
    "disableCache": true,
    "tag": "dns-in"
  },
  "routing": {
    "domainStrategy": "IPifNonMatch",
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
        "outboundTag": "block",
        "ip": [
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "protocol": [
          "bittorrent",
          "ed2k",
          "eDonkey",
          "thunder"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "protocol": [
          "quic",
          "stun",
          "dtls"
        ]
      }
    ]
  },
  "inbounds": [
    {
      "tag": "TROJAN_WS",
      "listen": "127.0.0.1",
      "port": 3001,
      "reuseport": true,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "sockopt": {
          "tcpFastOpen": true
        },
        "wsSettings": {
          "path": "/trojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "VMESS_WS",
      "listen": "127.0.0.1",
      "port": 3002,
      "reuseport": true,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "sockopt": {
          "tcpFastOpen": true
        },
        "wsSettings": {
          "path": "/vmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "VLESS_WS",
      "listen": "127.0.0.1",
      "port": 3003,
      "reuseport": true,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "sockopt": {
          "tcpFastOpen": true
        },
        "wsSettings": {
          "path": "/vless"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "TROJAN_UPGRADE",
      "listen": "127.0.0.1",
      "port": 3004,
      "reuseport": true,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "sockopt": {
          "tcpFastOpen": true
        },
        "httpupgradeSettings": {
          "path": "/uptrojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "VMESS_UPGRADE",
      "listen": "127.0.0.1",
      "port": 3005,
      "reuseport": true,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "sockopt": {
          "tcpFastOpen": true
        },
        "httpupgradeSettings": {
          "path": "/upvmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "VLESS_UPGRADE",
      "listen": "127.0.0.1",
      "port": 3006,
      "reuseport": true,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "sockopt": {
          "tcpFastOpen": true
        },
        "httpupgradeSettings": {
          "path": "/upvless"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "TROJAN_GRPC",
      "listen": "127.0.0.1",
      "port": 3007,
      "reuseport": true,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "grpc-trojan"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "VMESS_GRPC",
      "listen": "127.0.0.1",
      "port": 3008,
      "reuseport": true,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "grpc-vmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    },
    {
      "tag": "VLESS_GRPC",
      "listen": "127.0.0.1",
      "port": 3009,
      "reuseport": true,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "grpc-vless"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "metadataOnly": false,
        "domainsExcluded": [],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "AsIs"
      }
    },
    {
      "tag": "dns-out",
      "protocol": "dns",
      "settings": {
        "nonIPQuery": "skip"
      }
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "none"
        }
      }
    }
  ]
}
EOF

    # === Finalize Marzban ===
    log blue "Finalizing Marzban setup..."
    cd "$MARZBAN_DIR" || exit 1
    sed -i "s/# SUDO_USERNAME=admin/SUDO_USERNAME=${userpanel}/" .env
    sed -i "s/# SUDO_PASSWORD=admin/SUDO_PASSWORD=${passpanel}/" .env
    docker compose down && docker compose up -d || { log red "Failed to restart Marzban services."; exit 1; }
    marzban cli admin import-from-env -y || { log red "Failed to import admin from env."; exit 1; }
    sed -i "s/SUDO_USERNAME=${userpanel}/# SUDO_USERNAME=admin/" .env
    sed -i "s/SUDO_PASSWORD=${passpanel}/# SUDO_PASSWORD=admin/" .env
    docker compose down && docker compose up -d || { log red "Failed to restart Marzban services."; exit 1; }

    # === SQLite WAL Enable ===
    log blue "Waiting for Marzban database to be ready..."
    for i in {1..10}; do
        if docker exec marzban test -f /var/lib/marzban/db.sqlite3 2>/dev/null; then
            log green "Database detected"
            break
        fi
        sleep 2
    done

    current_mode=$(docker exec marzban python3 - << 'EOF'
import sqlite3
db = sqlite3.connect("/var/lib/marzban/db.sqlite3")
print(db.execute("PRAGMA journal_mode;").fetchone()[0])
db.close()
EOF
    )

    if [[ "$current_mode" == "wal" ]]; then
        log green "SQLite WAL mode already active"
    else
        log yellow "SQLite WAL not active — enabling now..."
        docker exec marzban python3 - << 'EOF'
import sqlite3, sys
db = sqlite3.connect("/var/lib/marzban/db.sqlite3")
mode = db.execute("PRAGMA journal_mode=WAL;").fetchone()[0]
if mode.lower() != "wal":
    print("FAILED: journal_mode =", mode)
    sys.exit(1)
db.execute("PRAGMA synchronous=NORMAL;")
db.execute("PRAGMA temp_store=MEMORY;")
db.execute("PRAGMA cache_size=-20000;")
db.close()
print("SQLite WAL ENABLED")
EOF
        if [[ $? -eq 0 ]]; then
            log green "SQLite WAL mode successfully enabled"
        else
            log red "Failed to enable SQLite WAL mode"
            exit 1
        fi
    fi

    log green "Marzban finalized with SQLite WAL persistent configuration"

    # === Firewall ===
    log blue "Configuring firewall..."
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 80/udp
    ufw allow 443/tcp
    ufw allow 443/udp
    ufw allow 2052/tcp
    ufw allow 2052/udp
    ufw allow 2053/tcp
    ufw allow 2053/udp
    ufw allow 2082/tcp
    ufw allow 2082/udp
    ufw allow 2083/tcp
    ufw allow 2083/udp
    ufw allow 2086/tcp
    ufw allow 2086/udp
    ufw allow 2087/tcp
    ufw allow 2087/udp
    ufw allow 2095/tcp
    ufw allow 2095/udp
    ufw allow 2096/tcp
    ufw allow 2096/udp
    ufw allow 8080/tcp
    ufw allow 8080/udp
    ufw allow 8880/tcp
    ufw allow 8880/udp
    ufw allow 8443/tcp
    ufw allow 8443/udp
    ufw allow 8000/tcp
    ufw allow 8010/tcp
    ufw allow 8010/udp
    ufw allow 3001:3009/tcp
    ufw allow 3001:3009/udp
    ufw --force enable || { log red "Failed to enable firewall."; exit 1; }

    # === Cleanup ===
    log blue "Cleaning up..."
    apt autoclean -y
    apt autoremove -y

    # === Install Summary ===
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

    # === Reboot Prompt ===
    read -rp "Reboot to apply changes? [default y] (y/n): " answer
	
	cat /dev/null > /root/.bash_history
	history -c
	rm -f "/root/install_wg.sh"
	
	if [[ "$answer" != "n" && "$answer" != "N" ]]; then
	    log blue "Rebooting system..."
		reboot
	fi
}

# === Error Trap ===
trap 'log red "Script terminated due to an error."; exit 1' ERR

# === Execute ===
main "$@"
