#!/bin/bash
set -e
# === Constants ===
CONFIG_DIR="/etc/data"
MARZBAN_DIR="/opt/marzban"
LOG_FILE="/root/log-install.txt"
DOMAIN_FILE="$CONFIG_DIR/domain"
USERPANEL_FILE="$CONFIG_DIR/userpanel"
PASSPANEL_FILE="$CONFIG_DIR/passpanel"
SUPPORTED_OS=("debian:10" "debian:11" "debian:12" "ubuntu:22.04" "ubuntu:24.04")

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

# === OS Check ===
check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        os_key="${ID}:${VERSION_ID}"

        for supported in "${SUPPORTED_OS[@]}"; do
            if [[ "$os_key" == "$supported" ]]; then
                return 0
            fi
        done
    fi

    log red "Error: This script only supports Debian 10/11/12 and Ubuntu 22.04/24.04."
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

# === Install Packages ===
install_packages() {
    log blue "Updating package lists..."
    apt-get update -y \
        || { log red "Failed to update package lists."; exit 1; }

    log blue "Installing required packages..."
    apt-get install -y sudo curl \
        || { log red "Failed to install sudo and curl."; exit 1; }

    log blue "Removing unused packages..."
    apt-get -y --purge remove samba* apache2* sendmail* bind9* \
        || log yellow "Note: Some packages couldn't be removed or weren't installed."

    log blue "Installing toolkit packages..."
    apt-get install -y \
        libio-socket-inet6-perl libsocket6-perl libcrypt-ssleay-perl \
        libnet-libidn-perl perl libio-socket-ssl-perl libwww-perl \
        libpcre3 libpcre3-dev zlib1g-dev dbus iftop zip unzip wget \
        net-tools nano sed screen gnupg gnupg1 bc build-essential \
        dirmngr dnsutils at htop iptables bsdmainutils cron \
        lsof lnav jq sqlite3 libsqlite3-dev \
        || { log red "Failed to install toolkit packages."; exit 1; }
    
    log blue "Installing speedtest..."
    wget -q https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz || { log red "Failed to download speedtest."; exit 1; }
    tar xzf ookla-speedtest-1.2.0-linux-x86_64.tgz > /dev/null 2>&1 || { log red "Failed to extract speedtest."; exit 1; }
    mv speedtest /usr/bin || { log red "Failed to install speedtest."; exit 1; }
    rm -f ookla-speedtest-1.2.0-linux-x86_64.tgz speedtest.* > /dev/null 2>&1
}

# === Network Tuning BBR ===
configure_network_bbr() {
    SYSCTL_SETTINGS=(
        "kernel.panic=10"
        "kernel.panic_on_oops=1"
        "kernel.printk=3 3 3 3"
        "fs.file-max=1048576"
        "vm.swappiness=10"
        "vm.dirty_ratio=30"
        "vm.dirty_background_ratio=5"
        "vm.vfs_cache_pressure=50"
        "net.core.netdev_max_backlog=5000"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
        "net.ipv4.tcp_max_syn_backlog=2048"
        "net.ipv4.tcp_fastopen=3"
        "net.ipv4.tcp_recovery=1"
        "net.ipv4.tcp_sack=1"
        "net.ipv4.tcp_dsack=1"
        "net.ipv4.tcp_slow_start_after_idle=0"
        "net.ipv4.tcp_no_metrics_save=1"
        "net.ipv4.tcp_mtu_probing=1"
        "net.ipv4.tcp_tw_reuse=1"
        "net.ipv4.ip_local_port_range=1024 65535"
        "net.ipv4.ip_forward=1"
    )

    for s in "${SYSCTL_SETTINGS[@]}"; do
        key="${s%%=*}"
        value="${s#*=}"
        sed_key="${key//./\\.}"

        sed -i "/^${sed_key}[[:space:]]*=/d" /etc/sysctl.conf
        echo "${key} = ${value}" >> /etc/sysctl.conf
    done

    sysctl -p >/dev/null 2>&1 || true

    grep -q "ulimit -SHn" /etc/profile || echo "ulimit -SHn 1000000" >> /etc/profile

    current_kernel=$(uname -r)
    check_algoritma=$(sysctl -n net.ipv4.tcp_congestion_control)

    log info "Current kernel   : $current_kernel"
    log info "Active algoritma : $check_algoritma"
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

    # === Configure Marzban Subs ===
    log blue "Configuring Marzban components..."
    wget -q -N -P /var/lib/marzban/templates/subscription/ https://raw.githubusercontent.com/wibusantun/Marzvps/main/index.html
    
    # === profile ===
    wget -O /usr/bin/profile "https://raw.githubusercontent.com/wibusantun/Marzvps/main/profile"
    chmod +x /usr/bin/profile
    wget -O /usr/bin/cekservice "https://raw.githubusercontent.com/wibusantun/Marzvps/main/cekservice.sh"
    chmod +x /usr/bin/cekservice

    # === Install vnStat ===
    log blue "Setting up system info display and vnStat..."

    apt install -y vnstat neofetch || log red "Failed to install vnStat or neofetch"

    IFACE=$(ip route | grep default | awk '{print $5}')
    log info "Using network interface: $IFACE"

    vnstat -u -i "$IFACE" >/dev/null 2>&1 || log yellow "vnStat database initialized"

    systemctl enable vnstat
    systemctl restart vnstat

    cat >> /root/.bash_profile <<'EOF'
[ -n "$PROFILE_LOADED" ] || { 
    export PROFILE_LOADED=1
    [ -f /usr/bin/profile ] && /usr/bin/profile
}
EOF

    log green "System info display and vnStat setup complete."

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
# UVICORN_SSL_CERTFILE=/var/lib/marzban/fullchain.pem
# UVICORN_SSL_KEYFILE=/var/lib/marzban/key.pem
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

SQLALCHEMY_DATABASE_URL="sqlite:////var/lib/marzban/db.sqlite3"
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
      - ./nginx.conf:/etc/nginx/nginx.conf
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
EOF

    # === Install Nginx ===
    log blue "Installing nginx..."
    mkdir -p /var/log/nginx /var/www/html
	touch /var/log/nginx/access.log
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

    chown -R www-data:www-data /var/www/html /var/log/nginx
    chmod -R 755 /var/www/html
	chmod -R 755 /var/log/nginx

    # nginx.conf
    cat > "$MARZBAN_DIR/nginx.conf" << 'EOF'
user www-data;
worker_processes 3;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
}

http {
    include                     mime.types;
    default_type                application/octet-stream;

    log_format main '[$time_local] $remote_addr "$http_referer" "$http_user_agent"';
    
    access_log                  /var/log/nginx/access.log main;

    sendfile                    on;
    tcp_nopush                  on;
    tcp_nodelay                 on;
    reset_timedout_connection   on;

    keepalive_timeout           65;
    keepalive_requests          1000;

    types_hash_max_size         2048;

    server_tokens               off;
    log_not_found               off;

    gzip                        off;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ""      close;
    }

    map $remote_addr $proxy_forwarded_elem {
        ~^[0-9.]+$         "for=$remote_addr";
        ~^[0-9A-Fa-f:.]+$  "for=\"[$remote_addr]\"";
        default            "for=unknown";
    }

    map $http_forwarded $proxy_add_forwarded {
        "~^(,[ \\t]*)*([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?(;([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?)*([ \\t]*,([ \\t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?(;([!#$%&'*+.^_`|~0-9A-Za-z-]+=([!#$%&'*+.^_`|~0-9A-Za-z-]+|\"([\\t \\x21\\x23-\\x5B\\x5D-\\x7E\\x80-\\xFF]|\\\\[\\t \\x21-\\x7E\\x80-\\xFF])*\"))?)*)?)*$" "$http_forwarded, $proxy_forwarded_elem";
        default "$proxy_forwarded_elem";
    }

    server {
        listen 80;
        listen [::]:80;
        listen 2052;
        listen [::]:2052;
        listen 2082;
        listen [::]:2082;
        listen 2086;
        listen [::]:2086;
        listen 2095;
        listen [::]:2095;
        listen 8080;
        listen [::]:8080;
        listen 8880;
        listen [::]:8880;

        listen 2053 ssl reuseport;
        listen [::]:2053 ssl ipv6only=off reuseport;
        listen 2083 ssl reuseport;
        listen [::]:2083 ssl ipv6only=off reuseport;
        listen 2087 ssl reuseport;
        listen [::]:2087 ssl ipv6only=off reuseport;
        listen 2096 ssl reuseport;
        listen [::]:2096 ssl ipv6only=off reuseport;
        listen 8443 ssl reuseport;
        listen [::]:8443 ssl ipv6only=off reuseport;
        listen 443 ssl reuseport;
        listen [::]:443 ssl ipv6only=off reuseport;
        listen 443 quic reuseport;
        listen [::]:443 quic ipv6only=off reuseport;        
        http2 on;

        server_name 127.0.0.1 localhost;

        root /var/www/html;
        index index.html;

        add_header Alt-Svc 'h3=":443"; ma=86400' always;
        add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;
        add_header X-XSS-Protection '1; mode=block' always;
        add_header X-Content-Type-Options 'nosniff' always;
        add_header Referrer-Policy 'no-referrer-when-downgrade' always;
        add_header Permissions-Policy 'interest-cohort=()' always;
        add_header X-Frame-Options 'SAMEORIGIN' always;

        ssl_certificate              /var/lib/marzban/fullchain.pem;
        ssl_certificate_key          /var/lib/marzban/key.pem;
        ssl_protocols                TLSv1.2 TLSv1.3;
        ssl_ciphers                  TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers    on;
        ssl_session_tickets          off;
        ssl_session_timeout          1h;
        ssl_session_cache            shared:SSL:10m;
        ssl_buffer_size              4k;

        resolver                     1.1.1.1 valid=60s;
        resolver_timeout             2s;

        client_header_buffer_size    1k;
        large_client_header_buffers  4 32k;

        real_ip_header               X-Forwarded-For;
        set_real_ip_from             127.0.0.1;
        set_real_ip_from             103.22.200.0/22;
        set_real_ip_from             104.16.0.0/13;
        set_real_ip_from             104.24.0.0/14;
        set_real_ip_from             108.162.192.0/18;
        set_real_ip_from             131.0.72.0/22;
        set_real_ip_from             141.101.64.0/18;
        set_real_ip_from             162.158.0.0/15;
        set_real_ip_from             172.64.0.0/13;
        set_real_ip_from             173.245.48.0/20;
        set_real_ip_from             188.114.96.0/20;
        set_real_ip_from             190.93.240.0/20;
        set_real_ip_from             197.234.240.0/22;
        set_real_ip_from             198.41.128.0/17;
        set_real_ip_from             2400:cb00::/32;
        set_real_ip_from             2606:4700::/32;
        set_real_ip_from             2803:f800::/32;
        set_real_ip_from             2405:b500::/32;
        set_real_ip_from             2405:8100::/32;
        set_real_ip_from             2a06:98c0::/29;

        if ($scheme = http) {
            return 301 https://$host$request_uri;
        }

        location = /trojan {
            client_max_body_size             0;
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_socket_keepalive           on;
            proxy_redirect                   off;
            proxy_pass                       http://127.0.0.1:3001;
            proxy_http_version               1.1;
            proxy_set_header Host            $host;
            proxy_set_header Upgrade         $http_upgrade;
            proxy_set_header Connection      $connection_upgrade;
            proxy_set_header X-Real-IP       $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout               1h;
            proxy_send_timeout               1h;
        }

        location = /vmess {
            client_max_body_size             0;
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_socket_keepalive           on;
            proxy_redirect                   off;
            proxy_pass                       http://127.0.0.1:3002;
            proxy_http_version               1.1;
            proxy_set_header Host            $host;
            proxy_set_header Upgrade         $http_upgrade;
            proxy_set_header Connection      $connection_upgrade;
            proxy_set_header X-Real-IP       $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout               1h;
            proxy_send_timeout               1h;
        }

        location = /vless {
            client_max_body_size             0;
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_socket_keepalive           on;
            proxy_redirect                   off;
            proxy_pass                       http://127.0.0.1:3003;
            proxy_http_version               1.1;
            proxy_set_header Host            $host;
            proxy_set_header Upgrade         $http_upgrade;
            proxy_set_header Connection      $connection_upgrade;
            proxy_set_header X-Real-IP       $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout               1h;
            proxy_send_timeout               1h;
        }

        location = /uptrojan {
            client_max_body_size             0;
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_socket_keepalive           on;
            proxy_redirect                   off;
            proxy_pass                       http://127.0.0.1:3004;
            proxy_http_version               1.1;
            proxy_set_header Host            $host;
            proxy_set_header Upgrade         $http_upgrade;
            proxy_set_header Connection      $connection_upgrade;
            proxy_set_header X-Real-IP       $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout               1h;
            proxy_send_timeout               1h;
        }

        location = /upvmess {
            client_max_body_size             0;
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_socket_keepalive           on;
            proxy_redirect                   off;
            proxy_pass                       http://127.0.0.1:3005;
            proxy_http_version               1.1;
            proxy_set_header Host            $host;
            proxy_set_header Upgrade         $http_upgrade;
            proxy_set_header Connection      $connection_upgrade;
            proxy_set_header X-Real-IP       $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout               1h;
            proxy_send_timeout               1h;
        }

        location = /upvless {
            client_max_body_size             0;
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_socket_keepalive           on;
            proxy_redirect                   off;
            proxy_pass                       http://127.0.0.1:3006;
            proxy_http_version               1.1;
            proxy_set_header Host            $host;
            proxy_set_header Upgrade         $http_upgrade;
            proxy_set_header Connection      $connection_upgrade;
            proxy_set_header X-Real-IP       $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout               1h;
            proxy_send_timeout               1h;
        }

        location /grpc-trojan {
            client_max_body_size             0;
            if ($content_type !~ "application/grpc") {
                return 404;
            }
            grpc_socket_keepalive            on;
            grpc_pass                        127.0.0.1:3007;
            grpc_set_header X-Real-IP        $remote_addr;
            grpc_read_timeout                1h;
            grpc_send_timeout                1h;
            client_body_buffer_size          1m;
            client_body_timeout              1h;
        }

        location /grpc-vmess {
            client_max_body_size             0;
            if ($content_type !~ "application/grpc") {
                return 404;
            }
            grpc_socket_keepalive            on;
            grpc_pass                        127.0.0.1:3008;
            grpc_set_header X-Real-IP        $remote_addr;
            grpc_read_timeout                1h;
            grpc_send_timeout                1h;
            client_body_buffer_size          1m;
            client_body_timeout              1h;
        }

        location /grpc-vless {
            client_max_body_size             0;
            if ($content_type !~ "application/grpc") {
                return 404;
            }
            grpc_socket_keepalive            on;
            grpc_pass                        127.0.0.1:3009;
            grpc_set_header X-Real-IP        $remote_addr;
            grpc_read_timeout                1h;
            grpc_send_timeout                1h;
            client_body_buffer_size          1m;
            client_body_timeout              1h;
        }

        location ~ ^/(dashboard|statics|api|docs|sub|redoc|openapi\.json) {
            proxy_pass                         http://127.0.0.1:8000;
            proxy_http_version                 1.1;
            proxy_set_header Host              $host;
            proxy_set_header Upgrade           $http_upgrade;
            proxy_set_header Connection        $connection_upgrade;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        }

        location ~ /\. {
            deny all;
        }
    }
}
EOF

    # === Auto Input server_name ===
    sed -i "s/server_name 127.0.0.1 localhost;/server_name $domain *.$domain;/" "$MARZBAN_DIR/nginx.conf"

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
    "servers": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "port": 53,
    "strategy": "UseIP",
    "disableCache": false,
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
        "port": 53,
        "network": "udp,tcp",
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
        "ip": [
          "geoip:id"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "port": "0-65535",
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
      "port": 3004,
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
      "port": 3005,
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
      "port": 3006,
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
    },
    {
      "tag": "TROJAN_GRPC",
      "listen": "127.0.0.1",
      "port": 3007,
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
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    },
    {
      "tag": "VMESS_GRPC",
      "listen": "127.0.0.1",
      "port": 3008,
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
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    },
    {
      "tag": "VLESS_GRPC",
      "listen": "127.0.0.1",
      "port": 3009,
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
        "domainStrategy": "UseIP"
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

    # === Token Helper ===
    get_token() {
        log blue "Generating API token..."
        for i in {1..30}; do
            token_json=$(curl -sf -X POST "https://${domain}/api/admin/token" \
                -H 'accept: application/json' \
                -H 'Content-Type: application/x-www-form-urlencoded' \
                -d "grant_type=password&username=${userpanel}&password=${passpanel}&scope=&client_id=string&client_secret=string")

            if [[ $? -eq 0 && -n "$token_json" ]]; then
                access_token=$(echo "$token_json" | jq -r '.access_token')
                if [[ -n "$access_token" && "$access_token" != "null" ]]; then
                    echo "$token_json" > /etc/data/token.json
                    log green "API token generated successfully!"
                    export access_token
                    return 0
                else
                    log yellow "API responded but no token yet. Retrying... ($i/30)"
                fi
            else
                log yellow "API not ready yet. Retrying... ($i/30)"
            fi
            sleep 2
        done
        log red "Failed to generate API token after multiple attempts."
        return 1
    }

    # === CALL TOKEN ===
    get_token || log yellow "Get Token..."

    # === Firewall ===
    log blue "Configuring firewall..."
    apt install -y ufw
    systemctl enable --now ufw >/dev/null 2>&1
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
    ufw --force enable || { log red "Failed to enable firewall."; exit 1; }

    # === Cleanup ===
    log blue "Cleaning up..."
    apt autoclean -y
    apt autoremove -y

    cd
    echo -e "login dashboard Marzban:"

	title="Marzban Dashboard Login Details:"
	u="URL: http://${domain}/dashboard"
	usr="Username: ${userpanel}"
	pw="Password: ${passpanel}"
	max_len=$(echo -e "${title}\n${u}\n${usr}\n${pw}" | wc -L)
	divider=$(printf '%*s' "$max_len" | tr ' ' '=')
cat <<EOF > "$LOG_FILE"
$title
$divider
$u
$usr
$pw
$divider
EOF
    cat "$LOG_FILE"

    # === Delete Admin Panel ===
    marzban cli admin delete -u admin -y 2>/dev/null || true
    colorized_echo green "Script successfully installed."
    : > /root/.bash_history
    history -c
    rm -f "/root/install.sh" 2>/dev/null || true

    read -rp "Reboot now? [Y/n]: " answer
    [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]] \
        && { echo "Rebooting..."; reboot; } \
        || echo "Reboot skipped."
}

# === Error Trap ===
trap 'log red "Script terminated due to an error."; exit 1' ERR

# === Execute ===
main "$@"
