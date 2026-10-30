#!/bin/bash
clear
echo -e " Selamat Datang Di \e[1;32mMarzban\e[0m Panel"
echo -e " Ketik \e[1;32mMarzban\e[0m untuk menampilkan daftar perintah"
echo -e ""
cekservice
cat /root/log-install-summary.txt
