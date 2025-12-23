# custom deap vpn 
curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh | sudo bash -s -- install


curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh | \
SE_USER=vpn SE_PASS=vpn SE_HUB=VPN SE_PORT=443 bash

# SSTP VPN быстро, просто, без лишней религии

Цель: поднять SSTP VPN (TCP/443) на SoftEther, чтобы клиенты Windows/Android/Linux подключались максимально просто.
Без заморочек с безопасностью (пароли будут в клиентских скриптах по желанию).

## Требования
- Debian 12 / Ubuntu (проверено на Debian 12)
- root-доступ
- Порт **443** должен быть свободен

---

# Установка

## Вариант 1: Интерактивная установка 
curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh | bash
## Вариант 2: Быстрая установка без вопросов
curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh | bash -s -- \
  --install \
  --host "YOURSERVERIP" \
  --adminpass "ADMINPASS" \
  --user "vpn" \
  --pass "vpn"
## Вариант 3
apt-get update && apt-get install -y git
git clone https://github.com/igruli0807/sstp-vpn.git
cd sstp-vpn
chmod +x install.sh
./install.sh


**Клиенты**
**Windows (PowerShell)**
В архиве softether-clients.zip:
server.cer
windows_sstp.ps1

Запуск:
распаковать архив
PowerShell:
.\windows_sstp.ps1
импортирует сертификат в CurrentUser\Root
создаёт SSTP-подключение
подключается (логин/пароль внутри)

**Linux (Debian/Ubuntu)**
В архиве:
linux_sstp.sh

Запуск:
sudo ./linux_sstp.sh

**Android**
Любой SSTP-клиент:
Server: <PUBLIC_HOST>
User/Pass: как создали
сертификат: либо импортировать server.cer (если приложение умеет), либо отключить проверку.

# Важно (честно и грустно)
- В “простом режиме” пароль хранится в клиентских скриптах.
- Сертификат самоподписанный, поэтому Windows будет ругаться, пока не импортируешь `server.cer`.
- Используется SecureNAT: это “VPN только для интернета”, без построения реальной сети.
