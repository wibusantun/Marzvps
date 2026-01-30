#!/bin/bash
domain=$(cat /etc/data/domain)
token=$(jq -r .access_token /etc/data/token.json)

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

ERROR="[${RED}ERROR${NC}]"; INFO="[${YELLOW}INFO${NC}]"; OKEY="[${GREEN}OKEY${NC}]"

# Service checks
[[ $(netstat -ntlp 2>/dev/null | grep nginx) ]] && NGINX="${GREEN}Okay${NC}" || NGINX="${RED}Not Okay${NC}"
[[ $(netstat -ntlp | grep -w 8000 | grep python) ]] && MARZ="${GREEN}Okay${NC}" || MARZ="${RED}Not Okay${NC}"
[[ $(systemctl is-active ufw) == "active" ]] && UFW="${GREEN}Okay${NC}" || UFW="${RED}Not Okay${NC}"

# === SYSTEM METRICS ===
UPTIME="$(uptime -p)"

MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_AVAILABLE=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
RAM_USED=$(echo "scale=1; (1 - $MEM_AVAILABLE / $MEM_TOTAL) * 100" | bc)

CPU_PREV=($(grep 'cpu ' /proc/stat))
sleep 1
CPU_NOW=($(grep 'cpu ' /proc/stat))
IDLE=$(( CPU_NOW[4] - CPU_PREV[4] ))
TOTAL=0
for ((i=1; i<${#CPU_NOW[@]}; i++)); do TOTAL=$(( TOTAL + CPU_NOW[i] - CPU_PREV[i] )); done
CPU_USED=$(echo "scale=1; (1 - $IDLE / $TOTAL) * 100" | bc)

# === FUNCTION: MARZBAN VERSION ===
function get_marzban_info() {
    local marzban_api="https://${domain}/api/system"
    local marzban_info=$(curl -s -X 'GET' "$marzban_api" -H 'accept: application/json' -H "Authorization: Bearer $token")
    if [[ $? -eq 0 ]]; then
        marzban_version=$(echo "$marzban_info" | jq -r '.version')
    else
        echo -e "${ERROR} Failed to fetch Marzban information."
        exit 1
    fi
}
get_marzban_info

# === MAP STABLE / BETA ===
versimarzban=$(grep 'image: gozargah/marzban:' /opt/marzban/docker-compose.yml | awk -F: '{print $3}')
case "${versimarzban}" in
    "latest") versimarzban="Stable";;
    "dev") versimarzban="Beta";;
esac

# === FUNCTION: XRAY CORE VERSION ===
function get_xray_core_version() {
    xray_core_info=$(curl -s -X 'GET' \
        "https://${domain}/api/core" \
        -H 'accept: application/json' \
        -H "Authorization: Bearer ${token}")
    xray_core_version=$(echo "$xray_core_info" | jq -r '.version')
}
get_xray_core_version

# === DISPLAY ===
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
echo -e "\E[42;1;30m            ⇱ Service Information ⇲             \E[0m"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
echo -e "❇️ Marzban Version     : ${GREEN}${marzban_version}${NC} (${BLUE}${versimarzban}${NC})"
echo -e "❇️ Core Version        : ${GREEN}Xray ${xray_core_version}${NC}"
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
