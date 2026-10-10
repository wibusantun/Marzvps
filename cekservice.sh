#!/bin/bash

# === CREDENTIALS ===
USERPANEL=$(cat /etc/data/userpanel 2>/dev/null)
PASSPANEL=$(cat /etc/data/passpanel 2>/dev/null)

# === COLORS ===
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# === DEFAULT VARIABLES ===
marzban_version="${RED}Unknown / API Offline${NC}"
xray_core_version="${RED}Unknown / API Offline${NC}"
token=""
MARZ_STATUS="DOWN"

# === SERVICE CHECKS ===
netstat -ntlp 2>/dev/null | grep -q nginx && NGINX="${GREEN}Okay${NC}" || NGINX="${RED}Not Okay${NC}"
systemctl is-active --quiet ufw 2>/dev/null && UFW="${GREEN}Okay${NC}" || UFW="${RED}Not Okay${NC}"

if netstat -ntlp 2>/dev/null | grep -w 8000 | grep -q python; then
    MARZ_STATUS="UP"
    MARZ="${GREEN}Okay${NC}"
else
    MARZ="${RED}Not Okay${NC}"
fi

# === DYNAMIC TOKEN GENERATOR ===
if [[ "$MARZ_STATUS" == "UP" && -n "$USERPANEL" && -n "$PASSPANEL" ]]; then
    token_json=$(curl -s --connect-timeout 1 -X POST "http://127.0.0.1:8000/api/admin/token" \
        -H 'accept: application/json' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "grant_type=password&username=${USERPANEL}&password=${PASSPANEL}&scope=&client_id=string&client_secret=string")

    if [[ -n "$token_json" ]]; then
        parsed_token=$(echo "$token_json" | jq -r '.access_token' 2>/dev/null)
        if [[ "$parsed_token" != "null" && -n "$parsed_token" ]]; then
            token="$parsed_token"
        fi
    fi
fi

# === SYSTEM METRICS ===
UPTIME="$(uptime -p | sed 's/up //; s/ years\?\,*/y/g; s/ weeks\?\,*/w/g; s/ days\?\,*/d/g; s/ hours\?\,*/h/g; s/ minutes\?\,*/m/g')"
MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_AVAILABLE=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
RAM_USED=$(echo "scale=1; (1 - $MEM_AVAILABLE / $MEM_TOTAL) * 100" | bc 2>/dev/null || echo "0")

read -r -a CPU_PREV <<< "$(grep 'cpu ' /proc/stat)"
sleep 1
read -r -a CPU_NOW <<< "$(grep 'cpu ' /proc/stat)"
IDLE=$(( CPU_NOW[4] - CPU_PREV[4] ))
TOTAL=0
for ((i=1; i<${#CPU_NOW[@]}; i++)); do TOTAL=$(( TOTAL + CPU_NOW[i] - CPU_PREV[i] )); done
CPU_USED=$(echo "scale=1; (1 - $IDLE / $TOTAL) * 100" | bc 2>/dev/null || echo "0")

# === API INFO ===
if [[ -n "$token" ]]; then
    marzban_info=$(curl -s --connect-timeout 1 -X 'GET' "http://127.0.0.1:8000/api/system" -H 'accept: application/json' -H "Authorization: Bearer $token")
    if [[ -n "$marzban_info" ]]; then
        mz_ver=$(echo "$marzban_info" | jq -r '.version' 2>/dev/null)
        [[ "$mz_ver" != "null" && -n "$mz_ver" ]] && marzban_version="${GREEN}${mz_ver}${NC}"
    fi

    xray_core_info=$(curl -s --connect-timeout 1 -X 'GET' "http://127.0.0.1:8000/api/core" -H 'accept: application/json' -H "Authorization: Bearer $token")
    if [[ -n "$xray_core_info" ]]; then
        xr_ver=$(echo "$xray_core_info" | jq -r '.version' 2>/dev/null)
        [[ "$xr_ver" != "null" && -n "$xr_ver" ]] && xray_core_version="${GREEN}Xray ${xr_ver}${NC}"
    fi
fi

# === MAP STABLE / BETA ===
versimarzban=$(grep 'image: gozargah/marzban:' /opt/marzban/docker-compose.yml 2>/dev/null | awk -F: '{print $3}')
case "${versimarzban}" in
    "latest") versimarzban="Stable";;
    "dev") versimarzban="Beta";;
    *) versimarzban="Unknown";;
esac

# === DISPLAY ===
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
echo -e "\E[42;1;30m            ⇱ Service Information ⇲             \E[0m"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
echo -e "❇️ Marzban Version     : ${marzban_version} (${BLUE}${versimarzban}${NC})"
echo -e "❇️ Core Version        : ${xray_core_version}"
echo -e "❇️ Nginx               : ${NGINX}"
echo -e "❇️ Firewall            : ${UFW}"
echo -e "❇️ Marzban Panel       : ${MARZ}"
echo -e "❇️ CPU Usage           : ${RED}${CPU_USED}%${NC}"
echo -e "❇️ RAM Usage           : ${GREEN}${RAM_USED}%${NC}"
echo -e "❇️ Uptime              : ${YELLOW}${UPTIME}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
echo -e "\E[42;1;30m                                                \E[0m"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
echo ""