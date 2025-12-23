# custom deap vpn 
# SSTP VPN быстро, просто, без лишней религии
# Вариант 1
curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh -o install.sh
chmod +x install.sh
./install.sh
# Вариант 2
curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh | bash -s -- \
  --install --host "ТВОЙ_ПУБЛИК_IP" --adminpass "АДМИН_ПАСС" --user "vpn" --pass "vpn"
# Вариант 3
bash -c "$(curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh)"


## Требования
- Debian 12 / Ubuntu (проверено на Debian 12)
- root-доступ
- Порт **443** должен быть свободен


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
