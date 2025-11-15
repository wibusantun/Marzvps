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
 Catatan
   ```html
 edit dan sesuaikan dgn script dibagian PRIV,PUB Key,IPv6 dan Reserve end di json Marzban Panel
 Notes,
 Untuk ipv6 Ganti domain strategy Wireguard (ForceIPv6v4) dan untuk ipv4 (ForceIP).
 ```