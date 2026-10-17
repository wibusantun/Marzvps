# Instalasi
Tested Ubuntu 20.04,22.04,24.04 & Debian 10/11/12

 Installasi
 ```html
{
   source /etc/os-release
   if [[ "$VERSION_ID" == "10" ]]; then
       cat <<EOF > /etc/apt/sources.list
deb http://archive.debian.org/debian buster main contrib non-free
deb http://archive.debian.org/debian-security buster/updates main
EOF
   elif [[ "$VERSION_ID" == "11" ]]; then
       cat <<EOF > /etc/apt/sources.list
deb http://archive.debian.org/debian bullseye main contrib non-free
deb http://archive.debian.org/debian-security bullseye-security main contrib non-free
EOF
   elif [[ "$ID" == "ubuntu" ]]; then
       if [ -f /etc/apt/sources.list ]; then
           sed -E -i 's|https?://[a-zA-Z0-9.-]+/ubuntu/?|http://archive.ubuntu.com/ubuntu/|g' /etc/apt/sources.list
       fi
       if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
           sed -E -i 's|https?://[a-zA-Z0-9.-]+/ubuntu/?|http://archive.ubuntu.com/ubuntu/|g' /etc/apt/sources.list.d/ubuntu.sources
       fi
   fi
   echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive
   rm -rf /var/lib/apt/lists/*
   apt clean
   apt update -y
} && apt install -y tmux wget unzip curl jq && \
(tmux has-session -t marzban_install 2>/dev/null && tmux attach -t marzban_install) || \
tmux new-session -s marzban_install "wget https://raw.githubusercontent.com/wibusantun/Marzvps/main/install.sh -O install.sh && chmod +x install.sh && ./install.sh; read -p 'Press Enter to exit...'"
 ```
  Untuk resume/lanjut Installasi Kalau Error
 ```html
 tmux attach -t marzban_install
  ```
 WARP-KEY
 ```html
 bash -c "$(curl -L warp-reg.vercel.app)"
  ```
