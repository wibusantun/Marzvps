# Instalasi
Tested Ubuntu 20,22,24 & Debian 10,11,12

Jangan Lupa Swap_Ram VPS Sebelum Install

Update dulu
  ```html
 apt-get update && apt-get upgrade -y && apt dist-upgrade -y && update-grub && reboot
 ```
 Tanpa WARP
 ```html
 wget https://raw.githubusercontent.com/wibusantun/Marzvps/main/install.sh && chmod +x install.sh && ./install.sh
 ```
 Dengan WARP
 ```html
 wget https://raw.githubusercontent.com/wibusantun/Marzvps/main/install_wg.sh && chmod +x install_wg.sh && ./install_wg.sh
 ```
 WARP-KEY
 ```html
 bash -c "$(curl -L warp-reg.vercel.app)"
  ```
 Pragma-Journal WAL
 ```html
 docker exec marzban python3 -c 'import sqlite3; db = sqlite3.connect("/var/lib/marzban/db.sqlite3"); db.execute("PRAGMA journal_mode = WAL;")'
  ```