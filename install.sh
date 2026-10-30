#!/bin/bash
set -Ee -o pipefail
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
        "red")     printf '\e[91m%s\e[0m\n' "$text";;
        "green")   printf '\e[92m%s\e[0m\n' "$text";;
        "yellow")  printf '\e[93m%s\e[0m\n' "$text";;
        "blue")    printf '\e[94m%s\e[0m\n' "$text";;
        "magenta") printf '\e[95m%s\e[0m\n' "$text";;
        "cyan")    printf '\e[96m%s\e[0m\n' "$text";;
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

# === Crontab Safe Replacer ===
replace_root_crontab_entry() {
    local marker="$1" entry="$2" current="" err_file rc
    command -v crontab >/dev/null 2>&1 || {
        log error "Required command crontab is missing."
        return 1
    }

    err_file=$(mktemp)
    if current=$(crontab -l 2>"$err_file"); then
        :
    else
        rc=$?
        if grep -qi 'no crontab for' "$err_file"; then
            current=""
        else
            cat "$err_file" >&2
            rm -f "$err_file"
            log error "Cannot read root crontab (exit $rc)."
            return "$rc"
        fi
    fi
    rm -f "$err_file"

    current=$(printf '%s\n' "$current" | grep -Fv -- "$marker" || :)
    {
        [[ -z "$current" ]] || printf '%s\n' "$current"
        printf '%s\n' "$entry"
    } | crontab -
}

# === Firewall Check ===
check_firewall_manager() {
    local unit enabled_state
    for unit in nftables.service firewalld.service netfilter-persistent.service; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            log error "$unit is active. UFW must be the only firewall policy manager."
            return 1
        fi
        enabled_state=$(systemctl is-enabled "$unit" 2>/dev/null || :)
        case "$enabled_state" in
            enabled|enabled-runtime|linked|linked-runtime|alias)
                log error "$unit is enabled at boot (state: $enabled_state)."
                return 1
                ;;
        esac
    done
    return 0
}

check_firewall_owner() {
    local iptables_version
    check_firewall_manager || return 1
    if ! iptables_version=$(iptables -V); then
        log error "Unable to query iptables backend."
        return 1
    fi
    case "$iptables_version" in
        *nf_tables*)
            log info "iptables backend: nf_tables."
            ;;
        *legacy*)
            log warning "iptables backend: legacy."
            ;;
        *)
            log warning "Unrecognized iptables backend string: $iptables_version"
            ;;
    esac
    return 0
}

ufw_mss_rule() {
    local file="$1" restore_cmd="$2"
    local rule='-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'
    local tmp backup

    [[ -f "$file" ]] || {
        log error "Missing UFW rules file: $file"
        return 1
    }

    if awk '
        /^\*mangle[[:space:]]*$/ { in_mangle=1; next }
        /^\*/ { in_mangle=0 }
        in_mangle && /--clamp-mss-to-pmtu/ { found=1 }
        END { exit !found }
    ' "$file"; then
        log info "MSS clamp already exists in $file."
        "$restore_cmd" --test < "$file"
        return 0
    fi

    tmp=$(mktemp "${file}.XXXXXX")
    if grep -Eq '^\*mangle[[:space:]]*$' "$file"; then
        if ! awk -v rule="$rule" '
            /^\*mangle[[:space:]]*$/ { in_mangle=1; print; next }
            in_mangle && /^COMMIT[[:space:]]*$/ && !inserted {
                print rule
                inserted=1
                in_mangle=0
                print
                next
            }
            { print }
            END { if (!inserted) exit 42 }
        ' "$file" > "$tmp"; then
            rm -f "$tmp"
            log error "Found an existing mangle table without a safe insertion point in $file."
            return 1
        fi
    else
        cat "$file" > "$tmp"
        printf '\n*mangle\n:POSTROUTING ACCEPT [0:0]\n%s\nCOMMIT\n' "$rule" >> "$tmp"
    fi

    chmod --reference="$file" "$tmp"
    chown --reference="$file" "$tmp"
    if ! "$restore_cmd" --test < "$tmp"; then
        rm -f "$tmp"
        log error "UFW MSS rule failed ${restore_cmd} syntax validation."
        return 1
    fi

    backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$file" "$backup"
    mv -f "$tmp" "$file"
    log info "MSS clamp installed in $file."
}

# === Root Check ===
check_root() {
    if [[ $EUID -ne 0 ]]; then
        colorized_echo red "Error: This script must be run as root."
        exit 1
    fi
}

# === OS Check ===
check_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        os_key="${ID}:${VERSION_ID}"

        case "$os_key" in
            debian:10|debian:11|ubuntu:20.04)
                log warning "$os_key is EOL / outside standard support. Ensure repository mirrors are functional."
                ;;
        esac

        for supported in "${SUPPORTED_OS[@]}"; do
            if [[ "$os_key" == "$supported" ]]; then
                return 0
            fi
        done
    fi

    log red "Error: This script only supports Debian 10/11/12 and Ubuntu 20.04/22.04/24.04."
    exit 1
}

# === Masked Password ===
read_password_mask() {
    local prompt="$1"
    local char
    PASSWORD_INPUT=""
    printf '%s' "$prompt"
    while IFS= read -r -s -n 1 char; do
        [[ -z "$char" ]] && break
        case "$char" in
            $'\177'|$'\b')
                if [[ -n "$PASSWORD_INPUT" ]]; then
                    PASSWORD_INPUT="${PASSWORD_INPUT%?}"
                    printf '\b \b'
                fi
                ;;
            *)
                PASSWORD_INPUT+="$char"
                printf '*'
                ;;
        esac
    done
    printf '\n'
}

# === Validation ===
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log red "Error: Invalid domain format."
        return 1
    fi
    return 0
}

validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log red "Error: Invalid email format."
        return 1
    fi
    return 0
}

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
    
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a

    apt-get update -y

    log blue "Removing unused packages..."
    apt-get -y --purge remove "samba*" "apache2*" "sendmail*" "bind9*" || true

    log blue "Installing core dependencies..."
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        ca-certificates apt-transport-https lsb-release gnupg gnupg2 dirmngr                     \
        iptables nftables ipset kmod openssh-server iproute2 procps                              \
        rsyslog openssl python3 python3-systemd python3-pyinotify                                \
        curl wget dnsutils socat ethtool net-tools lsof iftop vnstat                             \
        tar unzip zip xz-utils jq bc sqlite3 inotify-tools ufw fail2ban                          \
        sudo nano sed cron dbus screen htop lnav build-essential                                 \
        bash-completion                                                                          \
        || { log error "Failed to install packages."; exit 1; }

    log blue "Installing Ookla Speedtest CLI..."
    SPEEDTEST_URL="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
    SPEEDTEST_ARCHIVE="ookla-speedtest-1.2.0-linux-x86_64.tgz"
    TMP_DIR="$(mktemp -d)"
    if [ "$(uname -m)" != "x86_64" ]; then
        rm -rf "$TMP_DIR"
        log error "Speedtest binary requires x86_64 architecture."
        exit 1
    fi

    wget -q -O "$TMP_DIR/$SPEEDTEST_ARCHIVE" "$SPEEDTEST_URL" || { rm -rf "$TMP_DIR"; log error "Failed to download Ookla Speedtest."; exit 1; }
    tar -xzf "$TMP_DIR/$SPEEDTEST_ARCHIVE" -C "$TMP_DIR" speedtest || { rm -rf "$TMP_DIR"; log error "Failed to extract Speedtest."; exit 1; }
    install -m 0755 "$TMP_DIR/speedtest" /usr/bin/speedtest || { rm -rf "$TMP_DIR"; log error "Failed to install Speedtest."; exit 1; }
    rm -rf "$TMP_DIR"
    log green "Ookla Speedtest installed successfully."
}

# === Network Tuning (BBR & Sysctl) ===
configure_network_bbr() {

    local SYSCTL_FILE="/etc/sysctl.d/bbr-network-tuning.conf"
    local MODULES_FILE="/etc/modules-load.d/bbr.conf"
    local s key value escaped_key
    install -d -m 0755 /etc/sysctl.d
    modprobe tcp_bbr 2>/dev/null || true

    if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "bbr"; then
        log error "TCP BBR is unavailable in the running kernel."
        return 1
    fi

    if ! grep -Fxq "tcp_bbr" "$MODULES_FILE" 2>/dev/null; then
        echo "tcp_bbr" >> "$MODULES_FILE" || {
            log error "Failed to persist TCP BBR module loading."
            return 1
        }
    fi

    SYSCTL_SETTINGS=(
        "kernel.panic=10"
        "kernel.panic_on_oops=1"
        "kernel.printk=3 3 3 3"
        "fs.file-max=1048576"
        "vm.swappiness=50"
        "vm.vfs_cache_pressure=100"
        "vm.page-cluster=0"
        "vm.watermark_boost_factor=0"
        "vm.watermark_scale_factor=125"
        "vm.dirty_ratio=10"
        "vm.dirty_background_ratio=5"
        "vm.min_free_kbytes=65536"
        "net.core.netdev_max_backlog=5000"
        "net.core.somaxconn=4096"
        "net.core.rmem_max=6291456"
        "net.core.wmem_max=6291456"
        "net.core.rmem_default=262144"
        "net.core.wmem_default=262144"
        "net.core.optmem_max=65536"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_max_syn_backlog=4096"
        "net.ipv4.tcp_max_tw_buckets=32768"
        "net.ipv4.tcp_congestion_control=bbr"
        "net.ipv4.tcp_rmem=4096 87380 6291456"
        "net.ipv4.tcp_wmem=4096 65536 6291456"
        "net.ipv4.tcp_fastopen=3"
        "net.ipv4.tcp_timestamps=1"
        "net.ipv4.tcp_sack=1"
        "net.ipv4.tcp_dsack=1"
        "net.ipv4.tcp_fin_timeout=15"
        "net.ipv4.tcp_keepalive_time=300"
        "net.ipv4.tcp_keepalive_probes=5"
        "net.ipv4.tcp_keepalive_intvl=15"
        "net.ipv4.tcp_slow_start_after_idle=0"
        "net.ipv4.tcp_no_metrics_save=1"
        "net.ipv4.tcp_mtu_probing=1"
        "net.ipv4.tcp_tw_reuse=1"
        "net.ipv4.tcp_syncookies=1"
        "net.ipv4.ip_local_port_range=10000 65000"
        "net.ipv4.ip_forward=1"
        "net.ipv6.conf.all.forwarding=1"
        "net.ipv6.conf.all.accept_ra=2"
        "net.ipv6.conf.default.accept_ra=2"
    )

    for s in "${SYSCTL_SETTINGS[@]}"; do
        key="${s%%=*}"
        value="${s#*=}"
        escaped_key="${key//./\\.}"

        if ! sysctl -n "$key" >/dev/null 2>&1; then
            log warning "Skipping unsupported sysctl parameter: $key"
            continue
        fi

        if ! sysctl -w "${key}=${value}" >/dev/null 2>&1; then
            log error "Failed to apply sysctl parameter: $key"
            return 1
        fi

        if grep -qE "^[[:space:]]*${escaped_key}[[:space:]]*=" "$SYSCTL_FILE"; then
            if ! sed -i -E "s|^[[:space:]]*${escaped_key}[[:space:]]*=.*|${key} = ${value}|" "$SYSCTL_FILE"; then
                log error "Failed to update sysctl parameter: $key"
                return 1
            fi
        else
            if ! echo "${key} = ${value}" >> "$SYSCTL_FILE"; then
                log error "Failed to add sysctl parameter: $key"
                return 1
            fi
        fi
    done

    if [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]]; then
        log info "BBR enabled and persistent."
    else
        log error "Failed to enable BBR."
        return 1
    fi

    return 0
}

# === Docker Daemon Defaults ===
write_docker_daemon_defaults() {
    install -m 0755 -d /etc/docker || {
        log error "Failed to create /etc/docker."
        return 1
    }

    # Preserve existing configuration.
    if [[ -e /etc/docker/daemon.json ]]; then
        log info "Existing /etc/docker/daemon.json preserved."
        return 0
    fi

    cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF
}

# === Docker Installer ===
install_docker() {
    log blue "Checking Docker installation..."
    if command -v docker >/dev/null 2>&1; then
        log green "Docker is already installed. Skipping."
        return 0
    fi
    if [[ ! -r /etc/os-release ]]; then
        log error "Cannot read /etc/os-release."
        return 1
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    local os_key="${ID}:${VERSION_ID}"
    case "$os_key" in
        debian:10|debian:11|ubuntu:20.04)
            log warning "Using manual Docker APT installation for $os_key."
            ;;
        debian:12|ubuntu:22.04|ubuntu:24.04)
            log info "Skipping manual Docker installation on $os_key."
            log info "marzban.sh @ install will install Docker if missing."
            write_docker_daemon_defaults || return 1
            return 0
            ;;
        *)
            log error "No Docker installation policy defined for $os_key."
            return 1
            ;;
    esac
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    log blue "Removing conflicting Docker packages..."
    apt-get -y --purge remove \
        docker.io docker-doc docker-compose docker-compose-v2 \
        podman-docker containerd runc || true
    if [[ -z "${VERSION_CODENAME:-}" ]]; then
        VERSION_CODENAME=$(lsb_release -cs 2>/dev/null) || {
            log error "Failed to resolve OS VERSION_CODENAME."
            return 1
        }
    fi
    log blue "Configuring Docker APT repository..."
    install -m 0755 -d /etc/apt/keyrings || return 1
    if ! curl -fsSL --connect-timeout 15 --max-time 120 \
        "https://download.docker.com/linux/${ID}/gpg" |
        gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg; then
        log error "Failed to download or import Docker GPG key."
        return 1
    fi
    chmod a+r /etc/apt/keyrings/docker.gpg
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable\n' \
        "$(dpkg --print-architecture)" "$ID" "$VERSION_CODENAME" \
        > /etc/apt/sources.list.d/docker.list
    log blue "Updating Docker APT repository..."
    if ! apt-get \
        -o Acquire::Retries=2 \
        -o Acquire::http::Timeout=20 \
        -o Acquire::https::Timeout=20 \
        update; then
        log error "Docker APT update failed."
        return 1
    fi
    log blue "Installing Docker packages..."
    if ! apt-get install -y \
        -o Acquire::Retries=2 \
        -o Acquire::http::Timeout=20 \
        -o Acquire::https::Timeout=20 \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        docker-ce docker-ce-cli containerd.io \
        docker-compose-plugin docker-buildx-plugin; then
        log error "Failed to install Docker manually."
        return 1
    fi
    write_docker_daemon_defaults || return 1
    log blue "Enabling Docker service..."
    if ! systemctl enable docker.service; then
        log error "Failed to enable Docker."
        return 1
    fi
    if ! systemctl restart docker.service; then
        log error "Docker failed to start."
        journalctl -u docker.service -n 80 --no-pager \
            >> "$LOG_FILE" 2>&1 || true
        return 1
    fi
    if ! docker info >/dev/null 2>&1; then
        log error "Docker daemon API is not responding."
        journalctl -u docker.service -n 80 --no-pager \
            >> "$LOG_FILE" 2>&1 || true
        return 1
    fi
    log green "Manual Docker installation completed successfully."
}

# === System Limits ===
configure_system_limits() {
    local limits_file="/etc/security/limits.d/99-limit.conf"
    local manager_dir="/etc/systemd/system.conf.d"
    local docker_dir="/etc/systemd/system/docker.service.d"
    local current_kernel check_algoritma
    install -d -m 0755 \
        /etc/security/limits.d \
        "$manager_dir" \
        "$docker_dir"
    if ! grep -Fqx 'ulimit -SHn 65535' /etc/profile; then
        printf '%s\n' 'ulimit -SHn 65535' >> /etc/profile
    fi
    printf '%s\n' \
        '* soft nofile 65535' \
        '* hard nofile 65535' \
        'root soft nofile 65535' \
        'root hard nofile 65535' \
        > "$limits_file"
    printf '%s\n' \
        '[Manager]' \
        'DefaultLimitNOFILE=65535' \
        > "$manager_dir/99-limit.conf"
    printf '%s\n' \
        '[Service]' \
        'LimitNOFILE=65535' \
        'LimitNPROC=65535' \
        > "$docker_dir/override.conf"
    systemctl daemon-reexec
    systemctl daemon-reload
    if ! systemctl restart docker.service; then
        log error "Failed to restart Docker after applying system limits."
        return 1
    fi
    current_kernel=$(uname -r)
    check_algoritma=$(sysctl -n net.ipv4.tcp_congestion_control)
    log info "Current kernel   : $current_kernel"
    log info "Active algorithm : $check_algoritma"
    log info "System limits configured successfully."
    return 0
}

# === Main ===
main() {
    clear
    check_root
    install -d -m 0700 "$CONFIG_DIR"
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    check_os

# === Inputs Domain User Panel ===
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
    read_password_mask "Enter Password Panel: "
    passpanel="$PASSWORD_INPUT"
    printf '%s\n' "$passpanel" > "$PASSPANEL_FILE"
    chmod 600 "$DOMAIN_FILE" "$USERPANEL_FILE" "$PASSPANEL_FILE"

# === Preparation ===
    clear
    cd || exit 1
    log blue "Setting timezone to Asia/Jakarta..."
    timedatectl set-timezone Asia/Jakarta || { log error "Failed to set timezone."; exit 1; }

    if [[ -n "$TMUX" ]]; then
        tmux setenv -g TZ "Asia/Jakarta"
        tmux refresh-client -S
    fi

    log blue "Configuring and syncing NTP time..."
    systemctl restart systemd-timesyncd 2>/dev/null || true
    
    if ! timedatectl set-ntp true 2>/dev/null; then
        log yellow "timedatectl NTP failed, forcing sync via chrony..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y chrony 2>/dev/null || true
        systemctl restart chrony 2>/dev/null || true
        chronyc makestep || log yellow "NTP sync skipped, system time might need manual check."
    fi
    
    install_packages
    check_firewall_manager
    configure_network_bbr
    install_docker
    # === Install Marzban ===
    log blue "Installing Marzban..."
    if ! MARZBAN_INSTALLER=$(curl -fsSL --retry 3 \
        https://raw.githubusercontent.com/wibusantun/Marzvps/main/marzban.sh); then
        log error "Failed to download the Marzban installer."
        exit 1
    fi

    if ! bash -c "$MARZBAN_INSTALLER" @ install; then
        log error "The Marzban installer returned a failure."
        exit 1
    fi

    configure_system_limits
    
    log blue "Configuring Marzban Subscription Theme..."
    wget -q -N -P /var/lib/marzban/templates/subscription/ https://raw.githubusercontent.com/wibusantun/Marzvps/main/index.html

    wget -qO /usr/bin/profile "https://raw.githubusercontent.com/wibusantun/Marzvps/main/profile" && chmod +x /usr/bin/profile
    wget -qO /usr/bin/cekservice "https://raw.githubusercontent.com/wibusantun/Marzvps/main/cekservice.sh" && chmod +x /usr/bin/cekservice

    log blue "Setting up system info display and vnStat..."
    IFACE=$( { ip -4 route show default; ip -6 route show default; } 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n 1 )
    if [[ -n "$IFACE" ]]; then
        log info "Using network interface: $IFACE"
        if ! vnstat -u -i "$IFACE" >/dev/null 2>&1; then
            log warning "vnStat database initialized or failed on $IFACE."
        fi
    else
        log warning "No default-route interface was detected; skipping vnStat database initialization."
    fi

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
# === Environment Variable ===
    cat > "$MARZBAN_DIR/.env" << 'EOF'
UVICORN_HOST=127.0.0.1
UVICORN_PORT=7575
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
# JWT_ACCESS_TOKEN_EXPIRE_MINUTES=1440

# JOB_CORE_HEALTH_CHECK_INTERVAL=10
# JOB_RECORD_NODE_USAGES_INTERVAL=30
# JOB_RECORD_USER_USAGES_INTERVAL=10
# JOB_REVIEW_USERS_INTERVAL=10
# JOB_SEND_NOTIFICATIONS_INTERVAL=30
EOF
    chmod 600 "$MARZBAN_DIR/.env"
# === Install Xray-Core ===
    mkdir -p /var/lib/marzban/xray-core
    cd /var/lib/marzban/xray-core
    wget -O xray.zip "https://raw.githubusercontent.com/wibusantun/Marzvps/main/Xray-linux-64.zip"
    unzip -oq xray.zip && chmod +x xray && rm -f xray.zip
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
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    volumes:
      - /var/lib/marzban:/var/lib/marzban
      - /var/run/marzban:/var/run/marzban
      - /etc/localtime:/etc/localtime:ro
    environment:
      - XRAY_EXECUTABLE_PATH=/var/lib/marzban/xray-core/xray
      - XRAY_ASSETS_PATH=/var/lib/marzban/xray-core
      - CUSTOM_TEMPLATES_DIRECTORY=/var/lib/marzban/templates
      - SUBSCRIPTION_PAGE_TEMPLATE=/subscription/index.html

  nginx:
    image: nginx:alpine
    container_name: nginx
    restart: always
    network_mode: host
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    volumes:
      - /var/lib/marzban:/var/lib/marzban:ro
      - /var/run/marzban:/var/run/marzban
      - /var/www/html:/var/www/html:ro
      - /var/lib/marzban/log/nginx:/var/log/nginx
      - ./nginx.conf:/etc/nginx/nginx.conf
      - /etc/localtime:/etc/localtime:ro
    command: /bin/sh -c "touch /var/log/nginx/access.log /var/log/nginx/error.log && chown 101:101 /var/log/nginx/access.log /var/log/nginx/error.log && exec nginx -g 'daemon off;'"
EOF
    if ! docker compose -f "$MARZBAN_DIR/docker-compose.yml" config --quiet; then
        log error "Docker Compose configuration validation failed."
        exit 1
    fi
    log info "Docker Compose configuration validated successfully."
# === Install Nginx & RAMDisk ===
    log blue "Installing Nginx & RAMDisk..."
    mkdir -p /var/www/html /var/run/marzban/ /var/lib/marzban/log/nginx
    grep -q "tmpfs /var/lib/marzban/log/nginx" /etc/fstab || echo "tmpfs /var/lib/marzban/log/nginx tmpfs defaults,size=30M,noatime,mode=0755,uid=101,gid=101 0 0" >> /etc/fstab
    mount -a
    touch /var/lib/marzban/log/nginx/access.log /var/lib/marzban/log/nginx/error.log
    chown 101:101 /var/lib/marzban/log/nginx/access.log /var/lib/marzban/log/nginx/error.log
    chmod 644 /var/lib/marzban/log/nginx/access.log /var/lib/marzban/log/nginx/error.log
    wget -qO /tmp/html.zip "https://raw.githubusercontent.com/wibusantun/Marzvps/main/html.zip"
    unzip -oq /tmp/html.zip -d /var/www/ && rm -f /tmp/html.zip
    chown -R root:root /var/www/html
    find /var/www/html -type d -exec chmod 755 {} \;
    find /var/www/html -type f -exec chmod 644 {} \;
    chmod 755 /var/run/marzban
    log blue "Setting up log rotation for RAMDisk..."
    replace_root_crontab_entry "var/lib/marzban/log/nginx" "0 * * * * truncate -s 0 /var/lib/marzban/log/nginx/access.log /var/lib/marzban/log/nginx/error.log && docker kill -s USR1 nginx >/dev/null 2>&1"

# === Nginx Configuration ===
    cat > "$MARZBAN_DIR/nginx.conf" << 'EOF'
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
}

http {
    include                      mime.types;
    default_type                 application/octet-stream;

    limit_req_zone $binary_remote_addr zone=api_limit:2m rate=3r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit:2m;
    limit_req_log_level error;
    limit_req_status 429;

    access_log                   /var/log/nginx/access.log;
    error_log                    /dev/stderr crit;
    error_log                    /var/log/nginx/error.log warn;

    sendfile                     on;
    tcp_nopush                   on;
    tcp_nodelay                  on;
    reset_timedout_connection    on;

    client_body_buffer_size      16k;
    client_header_buffer_size    1k;
    large_client_header_buffers  2 4k;

    keepalive_timeout            20;
    keepalive_requests           1000;

    types_hash_max_size          2048;

    server_tokens                off;
    log_not_found                off;

    gzip                         on;
    gzip_vary                    on;
    gzip_proxied                 any;
    gzip_comp_level              6;
    gzip_min_length              1024;
    gzip_types                   text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ""      close;
    }

    upstream grpc_trojan_backend {
        server unix:/var/run/marzban/trojan_grpc.sock;
        keepalive 32;
    }
    upstream grpc_vmess_backend {
        server unix:/var/run/marzban/vmess_grpc.sock;
        keepalive 32;
    }
    upstream grpc_vless_backend {
        server unix:/var/run/marzban/vless_grpc.sock;
        keepalive 32;
    }

    server {
        listen 80;
        listen [::]:80;

        server_name 127.0.0.1 localhost;

        return 301 https://$host$request_uri;
    }

    server {
        listen 127.0.0.1:10000 ssl proxy_protocol default_server reuseport;
        listen 0.0.0.0:443 quic reuseport;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;
        http2 on;
        http3 on;
        quic_retry on;

        server_name 127.0.0.1 localhost;

        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Alt-Svc 'h3=":443"; ma=86400' always;
        add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;

        ssl_certificate              /var/lib/marzban/fullchain.pem;
        ssl_certificate_key          /var/lib/marzban/key.pem;
        ssl_protocols                TLSv1.2 TLSv1.3;

        ssl_ecdh_curve               X25519:prime256v1:secp384r1;
        ssl_ciphers                  ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers    off;
        ssl_session_tickets          off;

        ssl_session_timeout          1d;
        ssl_session_cache            shared:SSL:10m;

        root /var/www/html;
        index index.html index.htm;
        charset utf-8;

        location ~* \.(jpg|jpeg|png|gif|ico|svg|webp|woff|woff2|ttf|eot|otf)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
            try_files $uri =404;
        }

        location / {
            limit_req zone=api_limit burst=10 nodelay;
            limit_conn conn_limit 5;
            try_files $uri $uri/ =444;
        }

        location = /trojan {
            access_log                               off;
            client_max_body_size                     0;
            if ($http_upgrade != "websocket") {
                return 444;
            }
            proxy_socket_keepalive                   on;
            proxy_buffering                          off;
            proxy_request_buffering                  off;
            proxy_redirect                           off;
            proxy_pass                               http://unix:/var/run/marzban/trojan_ws.sock:/trojan;
            proxy_http_version                       1.1;
            proxy_set_header Host                    $host;
            proxy_set_header Upgrade                 $http_upgrade;
            proxy_set_header Connection              $connection_upgrade;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Forwarded-For         $proxy_add_x_forwarded_for;
        }

        location = /vmess {
            access_log                               off;
            client_max_body_size                     0;
            if ($http_upgrade != "websocket") {
                return 444;
            }
            proxy_socket_keepalive                   on;
            proxy_buffering                          off;
            proxy_request_buffering                  off;
            proxy_redirect                           off;
            proxy_pass                               http://unix:/var/run/marzban/vmess_ws.sock:/vmess;
            proxy_http_version                       1.1;
            proxy_set_header Host                    $host;
            proxy_set_header Upgrade                 $http_upgrade;
            proxy_set_header Connection              $connection_upgrade;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Forwarded-For         $proxy_add_x_forwarded_for;
        }

        location = /vless {
            access_log                               off;
            client_max_body_size                     0;
            if ($http_upgrade != "websocket") {
                return 444;
            }
            proxy_socket_keepalive                   on;
            proxy_buffering                          off;
            proxy_request_buffering                  off;
            proxy_redirect                           off;
            proxy_pass                               http://unix:/var/run/marzban/vless_ws.sock:/vless;
            proxy_http_version                       1.1;
            proxy_set_header Host                    $host;
            proxy_set_header Upgrade                 $http_upgrade;
            proxy_set_header Connection              $connection_upgrade;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Forwarded-For         $proxy_add_x_forwarded_for;
        }

        location = /uptrojan {
            access_log                               off;
            client_max_body_size                     0;
            if ($http_upgrade != "websocket") {
                return 444;
            }
            proxy_socket_keepalive                   on;
            proxy_buffering                          off;
            proxy_request_buffering                  off;
            proxy_redirect                           off;
            proxy_pass                               http://unix:/var/run/marzban/trojan_up.sock:/uptrojan;
            proxy_http_version                       1.1;
            proxy_set_header Host                    $host;
            proxy_set_header Upgrade                 $http_upgrade;
            proxy_set_header Connection              $connection_upgrade;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Forwarded-For         $proxy_add_x_forwarded_for;
        }

        location = /upvmess {
            access_log                               off;
            client_max_body_size                     0;
            if ($http_upgrade != "websocket") {
                return 444;
            }
            proxy_socket_keepalive                   on;
            proxy_buffering                          off;
            proxy_request_buffering                  off;
            proxy_redirect                           off;
            proxy_pass                               http://unix:/var/run/marzban/vmess_up.sock:/upvmess;
            proxy_http_version                       1.1;
            proxy_set_header Host                    $host;
            proxy_set_header Upgrade                 $http_upgrade;
            proxy_set_header Connection              $connection_upgrade;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Forwarded-For         $proxy_add_x_forwarded_for;
        }

        location = /upvless {
            access_log                               off;
            client_max_body_size                     0;
            if ($http_upgrade != "websocket") {
                return 444;
            }
            proxy_socket_keepalive                   on;
            proxy_buffering                          off;
            proxy_request_buffering                  off;
            proxy_redirect                           off;
            proxy_pass                               http://unix:/var/run/marzban/vless_up.sock:/upvless;
            proxy_http_version                       1.1;
            proxy_set_header Host                    $host;
            proxy_set_header Upgrade                 $http_upgrade;
            proxy_set_header Connection              $connection_upgrade;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Forwarded-For         $proxy_add_x_forwarded_for;
        }

        location /grpc-trojan {
            access_log                               off;
            client_max_body_size                     0;
            if ($content_type !~ "application/grpc") {
                return 444;
            }
            grpc_socket_keepalive                    on;
            grpc_pass                                grpc://grpc_trojan_backend;
            grpc_set_header X-Real-IP                $remote_addr;
            grpc_read_timeout                        1h;
            grpc_send_timeout                        1h;
            client_body_timeout                      1h;
        }

        location /grpc-vmess {
            access_log                               off;
            client_max_body_size                     0;
            if ($content_type !~ "application/grpc") {
                return 444;
            }
            grpc_socket_keepalive                    on;
            grpc_pass                                grpc://grpc_vmess_backend;
            grpc_set_header X-Real-IP                $remote_addr;
            grpc_read_timeout                        1h;
            grpc_send_timeout                        1h;
            client_body_timeout                      1h;
        }

        location /grpc-vless {
            access_log                               off;
            client_max_body_size                     0;
            if ($content_type !~ "application/grpc") {
                return 444;
            }
            grpc_socket_keepalive                    on;
            grpc_pass                                grpc://grpc_vless_backend;
            grpc_set_header X-Real-IP                $remote_addr;
            grpc_read_timeout                        1h;
            grpc_send_timeout                        1h;
            client_body_timeout                      1h;
        }

        location ~ ^/(dashboard|statics|api|docs|sub|redoc|openapi\.json) {
            limit_req zone=api_limit burst=15 nodelay;
            limit_conn conn_limit 10;
            
            add_header Cache-Control "no-cache, no-store, must-revalidate";
            add_header Pragma "no-cache";
            add_header Expires "0";
            
            proxy_buffer_size                        8k;
            proxy_buffers                            4 8k;
            proxy_busy_buffers_size                  16k;
            
            proxy_pass                               http://127.0.0.1:7575;
            proxy_http_version                       1.1;
            proxy_set_header Host                    $host;
            proxy_set_header Upgrade                 $http_upgrade;
            proxy_set_header Connection              $connection_upgrade;
            proxy_set_header X-Real-IP               $remote_addr;
            proxy_set_header X-Forwarded-Proto       $scheme;
            proxy_set_header X-Forwarded-For         $proxy_add_x_forwarded_for;
        }

        location ~ /\.(?!well-known).* {
            deny all;
            access_log off;
            log_not_found off;
            return 444;
        }
    }
}
EOF

# === Install Marzban Socket Watcher ===
    log blue "Setting up Marzban Socket Watcher..."
    cat > /usr/local/bin/marzban-watcher.sh << 'EOF'
#!/bin/bash
TARGET_DIR="/var/run/marzban"

mkdir -p "$TARGET_DIR"
chmod 755 "$TARGET_DIR"

shopt -s nullglob
for socket_path in "$TARGET_DIR"/*.sock; do
    [[ -S "$socket_path" ]] || continue
    chown root:101 "$socket_path"
    chmod 660 "$socket_path"
done

inotifywait -m "$TARGET_DIR" -e create | while read -r directory event file; do
    if [[ "$file" == *.sock ]]; then
        chown root:101 "$TARGET_DIR/$file"
        chmod 660 "$TARGET_DIR/$file"
    fi
done
EOF

    chmod +x /usr/local/bin/marzban-watcher.sh
    cat > /etc/systemd/system/marzban-watcher.service << 'EOF'
[Unit]
Description=Automated Marzban Socket Permissions Watcher
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/marzban-watcher.sh
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable marzban-watcher.service
    systemctl start marzban-watcher.service
    log green "Marzban Socket Watcher setup complete and running."
# === Auto Input server_name ===
    sed -i "s/server_name 127.0.0.1 localhost;/server_name $domain *.$domain;/" "$MARZBAN_DIR/nginx.conf"

    log blue "Setting ownership and permissions for /var/lib/marzban..."
    chown root:root /var/lib/marzban || { log red "Failed to set ownership for /var/lib/marzban."; exit 1; }
    chmod 755 /var/lib/marzban || { log red "Failed to set permissions for /var/lib/marzban."; exit 1; }

    log blue "Installing acme.sh..."
    curl -s https://get.acme.sh | sh -s email="$email" || { log error "Failed to install acme.sh."; exit 1; }

    log blue "Issuing SSL certificate for $domain..."
    ~/.acme.sh/acme.sh --issue --force --standalone --server letsencrypt -k ec-256 -d "$domain" \
        --pre-hook 'if docker inspect nginx >/dev/null 2>&1; then docker stop nginx || exit 1; fi' \
        --post-hook 'if docker inspect nginx >/dev/null 2>&1; then docker start nginx || exit 1; fi' || { log error "Failed to issue SSL certificate."; exit 1; }
    log blue "Installing SSL certificate..."
    ~/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchain-file /var/lib/marzban/fullchain.pem \
        --key-file /var/lib/marzban/key.pem \
        --ecc || { log error "Failed to install SSL certificate."; exit 1; }

    log blue "Setting permissions for SSL certificate files..."
    chmod 600 /var/lib/marzban/key.pem || { log error "Failed to set permissions for key.pem."; exit 1; }
    chmod 644 /var/lib/marzban/fullchain.pem || { log error "Failed to set permissions for fullchain.pem."; exit 1; }
    log green "SSL certificate installation completed successfully."

# === Generating Xray Reality Keys ===
    log blue "Generating Xray Reality Keys..."
    REALITY_KEYS=$(/var/lib/marzban/xray-core/xray x25519)
    PRIVATE_KEY=$(echo "$REALITY_KEYS" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$REALITY_KEYS" | grep "Public key:" | awk '{print $3}')
    SHORT_ID=$(openssl rand -hex 8)
    log info "Reality Public Key: $PUBLIC_KEY"
    log info "Reality Short ID: $SHORT_ID"
    echo "Reality Public Key: $PUBLIC_KEY" >> "$LOG_FILE"
    echo "Reality Short ID: $SHORT_ID" >> "$LOG_FILE"

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
      "8.8.8.8",
      "2606:4700:4700::1111",
      "2001:4860:4860::8888",
      {
        "address": "localhost",
        "skipFallback": true
      }
    ],
    "hosts": {
      "one.one.one.one": "1.1.1.1",
      "dns.google": "8.8.8.8"
    },
    "port": 53,
    "queryStrategy": "UseIP",
    "disableCache": true,
    "tag": "dns-in"
  },
  "routing": {
    "domainStrategy": "AsIs",
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
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
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
        "network": "tcp,udp",
        "outboundTag": "direct"
      }
    ]
  },
  "inbounds": [
    {
      "tag": "VLESS_REALITY",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "sockopt": {
          "tcpFastOpen": true
        },
        "realitySettings": {
          "show": false,
          "dest": "127.0.0.1:10000",
          "xver": 1,
          "serverNames": [
            "on.zoom.us",
            "api.zoom.us",
            "aidoc.zoom.us",
            "graph.instagram.com",
            "b.i.instagram.com"
          ],
          "privateKey": "PRIVATE_KEY",
          "shortIds": [
            "SHORT_ID_PLACE"
          ]
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
      "tag": "TROJAN_WS",
      "listen": "/var/run/marzban/trojan_ws.sock",
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
      "listen": "/var/run/marzban/vmess_ws.sock",
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
      "listen": "/var/run/marzban/vless_ws.sock",
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
      "listen": "/var/run/marzban/trojan_up.sock",
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
      "listen": "/var/run/marzban/vmess_up.sock",
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
      "listen": "/var/run/marzban/vless_up.sock",
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
      "listen": "/var/run/marzban/trojan_grpc.sock",
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
      "listen": "/var/run/marzban/vmess_grpc.sock",
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
      "listen": "/var/run/marzban/vless_grpc.sock",
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
      "settings": {}
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

    # === Inject Private Key and Short ID to JSON ===
    sed -i "s/PRIVATE_KEY/$PRIVATE_KEY/" /var/lib/marzban/xray_config.json
    sed -i "s/SHORT_ID_PLACE/$SHORT_ID/" /var/lib/marzban/xray_config.json
    # === Validate Xray Configuration ===
    if ! jq -e . /var/lib/marzban/xray_config.json >/dev/null 2>&1; then
        log error "Xray JSON configuration is invalid."
        exit 1
    fi
    if [[ ! -s /var/lib/marzban/xray-core/geoip.dat ]]; then
        log error "geoip.dat is missing from the Xray assets directory."
        exit 1
    fi
    if ! XRAY_LOCATION_ASSET="/var/lib/marzban/xray-core" \
        /var/lib/marzban/xray-core/xray run -test \
        -config /var/lib/marzban/xray_config.json; then
        log error "Xray configuration validation failed."
        exit 1
    fi
    log info "Xray configuration validated successfully."
    # === Finalize Marzban ===
    log blue "Finalizing Marzban setup..."
    cd "$MARZBAN_DIR" || exit 1
    sed -i "s/# SUDO_USERNAME=admin/SUDO_USERNAME=${userpanel}/" .env
    sed -i "s/# SUDO_PASSWORD=admin/SUDO_PASSWORD=${passpanel}/" .env
    fuser -k 80/tcp 443/tcp 80/udp 443/udp 2>/dev/null || true
    if ! { docker compose down && docker compose up -d; }; then
        log error "Failed to restart Marzban services."
        exit 1
    fi
    log blue "Mengaktifkan mode WAL pada SQLite..."
    for _ in {1..30}; do
        if [[ -f /var/lib/marzban/db.sqlite3 ]]; then
            break
        fi
        sleep 1
    done

    if [[ -f /var/lib/marzban/db.sqlite3 ]]; then
        sqlite3 /var/lib/marzban/db.sqlite3 'PRAGMA journal_mode=WAL;'
        sqlite3 /var/lib/marzban/db.sqlite3 'PRAGMA journal_mode;'
    else
        log yellow "Warning: db.sqlite3 not found yet, skipping WAL mode configuration..."
    fi
    marzban cli admin import-from-env -y || { log error "Failed to import admin from env."; exit 1; }
    sed -i "s/SUDO_USERNAME=${userpanel}/# SUDO_USERNAME=admin/" .env
    sed -i "s/SUDO_PASSWORD=${passpanel}/# SUDO_PASSWORD=admin/" .env
    if ! { docker compose down && docker compose up -d; }; then
        log error "Failed to restart Marzban services."
        exit 1
    fi

    # === Build Live Web Stats ===
    log blue "Setting up Live Server Stats API ..."
    cat > /usr/local/bin/web-stats.sh << 'EOF'
#!/bin/bash

UPTIME=$(uptime -p | sed 's/up //; s/ years\?,*/y/g; s/ weeks\?,*/w/g; s/ days\?,*/d/g; s/ hours\?,*/h/g; s/ minutes\?,*/m/g')

RAM_USED=$(awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} END{printf "%.1f", 100*(1-a/t)}' /proc/meminfo)

read -r cpu user nice system idle rest <<< "$(head -n 1 /proc/stat)"
TOTAL1=$((user + nice + system + idle))
IDLE1=$idle
sleep 1
read -r cpu user nice system idle rest <<< "$(head -n 1 /proc/stat)"
TOTAL2=$((user + nice + system + idle))
IDLE2=$idle
CPU_USED=$(awk -v id1="$IDLE1" -v id2="$IDLE2" -v t1="$TOTAL1" -v t2="$TOTAL2" 'BEGIN {printf "%.1f", 100*(1-(id2-id1)/(t2-t1))}')

if [ "$(docker inspect -f '{{.State.Running}}' nginx 2>/dev/null)" = "true" ]; then
  NGINX="Online"
else
  NGINX="Offline"
fi

cat > /var/www/html/stats.json <<JSON
{
  "cpu": "${CPU_USED}%",
  "ram": "${RAM_USED}%",
  "uptime": "${UPTIME}",
  "nginx": "${NGINX}"
}
JSON
chmod 644 /var/www/html/stats.json
EOF

    chmod +x /usr/local/bin/web-stats.sh
    /usr/local/bin/web-stats.sh
    log blue "Adding Web Stats Generator to Cronjob..."
    replace_root_crontab_entry "/usr/local/bin/web-stats.sh" "*/5 * * * * /usr/local/bin/web-stats.sh"

    # === FIREWALL & MSS CLAMPING ===
    log blue "Configuring UFW and MSS Clamping..."

    check_firewall_owner
    ufw_mss_rule /etc/ufw/before.rules iptables-restore

    UFW_IPV6="no"
    if [[ -r /etc/default/ufw ]]; then
        UFW_IPV6=$(awk -F= '$1 == "IPV6" { gsub(/[[:space:]]/, "", $2); print tolower($2); exit }' /etc/default/ufw)
    fi
    if [[ "$UFW_IPV6" == "yes" ]]; then
        ufw_mss_rule /etc/ufw/before6.rules ip6tables-restore
    else
        log warning "UFW IPv6 is disabled; no live IPv6 MSS clamp will be expected."
    fi

    # === Fail2ban & UFW ===
    log blue "Configuring UFW and Fail2ban..."
    if ! SSHD_EFFECTIVE_CONFIG=$(sshd -T); then
        log error "sshd -T failed; refusing to enable UFW without a verified SSH port."
        return 1
    fi
    SSH_PORTS_TEXT=$(printf '%s\n' "$SSHD_EFFECTIVE_CONFIG" | awk '$1 == "port" { print $2 }' | sort -n -u)
    if [[ -z "$SSH_PORTS_TEXT" ]]; then
        log warning "Could not determine the effective SSH port. Falling back to port 22."
        SSH_PORTS_CSV="22"
        SSH_PORTS=("22")
    else
        mapfile -t SSH_PORTS <<< "$SSH_PORTS_TEXT"
        SSH_PORTS_CSV=$(printf '%s\n' "${SSH_PORTS[@]}" | paste -sd, -)
    fi

    ufw default deny incoming
    ufw default allow outgoing
    for SSH_PORT in "${SSH_PORTS[@]}"; do
        if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        log error "Invalid SSH port reported by sshd: $SSH_PORT"
        return 1
        fi
        ufw allow "${SSH_PORT}/tcp"
    done
    ufw allow 80/tcp
    ufw allow 80/udp
    ufw allow 443/tcp
    ufw allow 443/udp
    ufw route allow from 172.16.0.0/12 to any
    ufw logging off

    if ! ufw --force enable; then
        log error "Failed to enable UFW."
        return 1
    fi
    if ! ufw reload; then
        log error "UFW reload failed; do not continue to production."
        return 1
    fi
    systemctl enable ufw

    log green "UFW configured successfully (SSH Ports: ${SSH_PORTS_CSV})."

    # === FAIL2BAN ===
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 24h
findtime = 10m
maxretry = 3
banaction = ufw
banaction_allports = ufw

[sshd]
enabled = true
port    = $SSH_PORTS_CSV
filter  = sshd
maxretry = 3
backend = systemd

[nginx-limit-req]
enabled = true
port    = http,https
filter  = nginx-limit-req
logpath = /var/lib/marzban/log/nginx/error.log
backend = auto
maxretry = 5
bantime = 24h
findtime = 10m
EOF

    log blue "Applying Sync Fail2ban with RAMDisk..."
    mkdir -p /etc/systemd/system/fail2ban.service.d
    cat > /etc/systemd/system/fail2ban.service.d/override.conf << 'EOF'
[Unit]
Requires=ufw.service
After=ufw.service local-fs.target
RequiresMountsFor=/var/lib/marzban/log/nginx

[Service]
ExecStartPre=/bin/mkdir -p /var/lib/marzban/log/nginx
ExecStartPre=/bin/touch /var/lib/marzban/log/nginx/access.log /var/lib/marzban/log/nginx/error.log
ExecStartPre=/bin/chown 101:101 /var/lib/marzban/log/nginx/access.log /var/lib/marzban/log/nginx/error.log
ExecStartPre=/bin/chmod 644 /var/lib/marzban/log/nginx/access.log /var/lib/marzban/log/nginx/error.log
EOF

    systemctl daemon-reload
    if ! fail2ban-client -t; then
        log error "Fail2ban configuration test failed."
        return 1
    fi
    
    systemctl enable fail2ban
    if ! systemctl restart fail2ban; then
        log error "Fail2ban failed to restart."
        return 1
    fi
    log green "Sync Fail2ban with UFW configured successfully."

    # === Cleanup ===
    log blue "Cleaning up..."
    apt autoclean -y
    apt autoremove -y

    cd
    echo -e "login dashboard Marzban:"

    title="Marzban Dashboard Login Details:"
    u="URL: https://${domain}/dashboard"
    usr="Username: ******"
    pw="Password: ******"
    pub="Reality Public Key: ${PUBLIC_KEY}"
    max_len=$(printf '%s\n%s\n%s\n%s\n%s\n' "$title" "$u" "$usr" "$pw" "$pub" | wc -L)
    divider=$(printf '%*s' "$max_len" "" | tr ' ' '=')
cat <<EOF > /root/log-install-summary.txt
$title
$divider
$u
$usr
$pw
$pub
$divider
EOF
    cat /root/log-install-summary.txt

    # === Delete Admin Panel ===
    if marzban cli admin delete -u admin -y; then
        log info "Removed the default admin account."
    fi
    colorized_echo green "Script successfully installed."
    : > ~/.bash_history 2>/dev/null || true
    { history -c; history -w; } 2>/dev/null || true
    rm -f "/root/install.sh" 2>/dev/null || true

    read -rp "Reboot now? [Y/n]: " answer
    if [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]; then
        echo "Rebooting..."
        reboot
    else
        echo "Reboot skipped."
    fi
}

# === Error Trap ===
trap 'rc=$?; log error "Script failed near line ${BASH_LINENO[0]:-$LINENO} (exit status $rc). Review the preceding command output and /root/log-install.txt."; exit "$rc"' ERR

# === Execute ===
main "$@"