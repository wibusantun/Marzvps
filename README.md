# Instalasi
Tested Ubuntu 22,24 & Debian 10,11,12

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
