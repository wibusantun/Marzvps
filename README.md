# Instalasi
Tested Ubuntu 20.4,22.04,24.4 & Debian 10/11/12

Repository Debian 10 (Khusus Debian 10)
Jika menggunakan Debian 10, jalankan perintah ini terlebih dahulu
 ```html
cat << 'EOF' > /etc/apt/sources.list
deb http://archive.debian.org/debian buster main contrib non-free
deb http://archive.debian.org/debian-security buster/updates main
EOF
  ```
Repository Debian 11 (Khusus Debian 11)
Jika menggunakan Debian 11, jalankan perintah ini terlebih dahulu
 ```html
cat << 'EOF' > /etc/apt/sources.list
deb http://archive.debian.org/debian bullseye main contrib non-free
deb http://archive.debian.org/debian-security bullseye-security main contrib non-free
EOF
  ```
Update dulu
  ```html
 apt-get update && apt-get upgrade -y && apt dist-upgrade -y && update-grub && reboot
 ```
 Installasi
 ```html
apt update -y && apt install -y tmux wget unzip curl -y && \
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
