#!/usr/bin/env bash
set -euo pipefail

# ===== Paths =====
VPNROOT="/usr/local/vpnserver"
VPNSRV="$VPNROOT/vpnserver/vpnserver"
VPNCMD="$VPNROOT/vpncmd/vpncmd"
SRCDIR="/usr/local/src/SoftEtherVPN_Stable"
UNIT="/etc/systemd/system/vpnserver.service"
STATE="/etc/softether-sstp.env"
CLIENT_DIR="/root/softether-clients"

# ===== Helpers =====
need_root() { [ "${EUID:-0}" -eq 0 ] || { echo "Запусти от root"; exit 1; }; }

tty_read() { local __v="$1" __p="$2"; read -r -p "$__p" "$__v" < /dev/tty; }

load_state() {
  if [ -f "$STATE" ]; then
    # shellcheck disable=SC1090
    source "$STATE"
  fi
}

save_state() {
  cat >"$STATE" <<EOF
ADMIN_PASS='${ADMIN_PASS}'
HUB_NAME='${HUB_NAME}'
PUBLIC_HOST='${PUBLIC_HOST}'
EOF
  chmod 600 "$STATE"
}

require_admin_pass() {
  load_state
  if [ -z "${ADMIN_PASS:-}" ]; then
    tty_read ADMIN_PASS "Пароль админа SoftEther SERVER: "
  fi
  if [ -z "${HUB_NAME:-}" ]; then
    HUB_NAME="VPN"
  fi
}

run_vpncmd_server() {
  "$VPNCMD" localhost /SERVER /PASSWORD:"$ADMIN_PASS" /CMD "$@"
}

run_vpncmd_hub() {
  "$VPNCMD" localhost /SERVER /PASSWORD:"$ADMIN_PASS" /HUB:"$HUB_NAME" /CMD "$@"
}

port_443_check() {
  if ss -lntp | awk '{print $4,$6}' | grep -qE '(:443)\b'; then
    echo "Порт 443 уже занят. Освободи 443 или меняй схему."
    ss -lntp | grep ':443' || true
    exit 1
  fi
}

# ===== Actions =====
install_softether() {
  need_root
  port_443_check

  apt-get update
  apt-get install -y git build-essential libreadline-dev libssl-dev zlib1g-dev \
    ca-certificates curl unzip

  # Build SoftEther if binaries missing
  if [ ! -x "$VPNSRV" ] || [ ! -x "$VPNCMD" ]; then
    rm -rf "$SRCDIR"
    git clone --depth 1 https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git "$SRCDIR"
    cd "$SRCDIR"
    ./configure
    make -j"$(nproc)"

    mkdir -p "$VPNROOT/vpnserver" "$VPNROOT/vpncmd"

    # Copy bin trees exactly
    cp -a "$SRCDIR/bin/vpnserver/"* "$VPNROOT/vpnserver/"
    cp -a "$SRCDIR/bin/vpncmd/"* "$VPNROOT/vpncmd/"

    chmod 700 "$VPNROOT/vpnserver/vpnserver" "$VPNROOT/vpncmd/vpncmd" || true
    chmod 600 "$VPNROOT/vpnserver/"*.key 2>/dev/null || true
  fi

  cat >"$UNIT" <<EOF
[Unit]
Description=SoftEther VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
WorkingDirectory=$VPNROOT/vpnserver
ExecStart=$VPNROOT/vpnserver/vpnserver start
ExecStop=$VPNROOT/vpnserver/vpnserver stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now vpnserver
}

initial_config() {
  need_root

  # Ask minimal params
  tty_read PUBLIC_HOST "PUBLIC_HOST (IP или домен для подключения SSTP): "
  tty_read ADMIN_PASS  "Задай пароль админа SoftEther SERVER: "
  HUB_NAME="VPN"

  # Set admin password (на новой установке старого нет, поэтому пускаем пустую строку в stdin)
  echo | "$VPNCMD" localhost /SERVER /CMD ServerPasswordSet "$ADMIN_PASS" >/dev/null

  # Create Hub if not exists
  run_vpncmd_server HubCreate "$HUB_NAME" /PASSWORD:"hubpass" >/dev/null 2>&1 || true

  # Enable SecureNAT (только интернет)
  run_vpncmd_hub SecureNatEnable >/dev/null 2>&1 || true

  # Enable SSTP
  run_vpncmd_server SstpEnable yes >/dev/null 2>&1 || true

  # Ensure listener 443 exists and enabled; remove other listeners (чтобы не торчало лишнее)
  run_vpncmd_server ListenerCreate 443 >/dev/null 2>&1 || true
  run_vpncmd_server ListenerEnable 443 >/dev/null 2>&1 || true
  for p in 5555 992 1194; do
    run_vpncmd_server ListenerDelete "$p" >/dev/null 2>&1 || true
  done

  # Regenerate server certificate with CN=PUBLIC_HOST (чтобы Windows SSTP не ругался на несоответствие имени)
  run_vpncmd_server ServerCertRegenerate /CN:"$PUBLIC_HOST" /O:none /OU:none /C:none /ST:none /L:none >/dev/null 2>&1 || true

  save_state

  # Create first user (asked in install flow)
  add_user

  # Generate client scripts bundle
  generate_clients
}

add_user() {
  need_root
  require_admin_pass
  load_state

  local u p
  tty_read u "Логин нового пользователя: "
  tty_read p "Пароль для '$u': "

  run_vpncmd_hub UserCreate "$u" /GROUP:none /REALNAME:none /NOTE:none >/dev/null 2>&1 || true
  run_vpncmd_hub UserPasswordSet "$u" /PASSWORD:"$p" >/dev/null

  echo "Пользователь создан/обновлён: $u"

  # Optional: update client scripts for this user (быстро и удобно)
  VPN_USER="$u"
  VPN_PASS="$p"
  generate_clients
}

del_user() {
  need_root
  require_admin_pass
  local u
  tty_read u "Логин пользователя на удаление: "
  run_vpncmd_hub UserDelete "$u" >/dev/null
  echo "Пользователь удалён: $u"
}

generate_clients() {
  need_root
  load_state

  # Need last created user creds; if absent, ask once.
  if [ -z "${VPN_USER:-}" ]; then tty_read VPN_USER "Логин для клиентских скриптов: "; fi
  if [ -z "${VPN_PASS:-}" ]; then tty_read VPN_PASS "Пароль для клиентских скриптов: "; fi
  if [ -z "${PUBLIC_HOST:-}" ]; then tty_read PUBLIC_HOST "PUBLIC_HOST (IP/домен): "; fi

  rm -rf "$CLIENT_DIR"
  mkdir -p "$CLIENT_DIR"

  # Export server certificate to file for Windows trust import
  run_vpncmd_server ServerCertGet "$CLIENT_DIR/server.cer" >/dev/null 2>&1 || {
    echo "Не удалось выгрузить сертификат (ServerCertGet)."
    exit 1
  }

  # Windows PowerShell script: imports cert, creates SSTP VPN, connects
  cat >"$CLIENT_DIR/windows_sstp.ps1" <<EOF
# Запускать PowerShell'ем от обычного пользователя.
# Пароль внутри. Ты сам так захотел.

\$VpnName = "SSTP-$PUBLIC_HOST"
\$Server  = "$PUBLIC_HOST"
\$User    = "$VPN_USER"
\$Pass    = "$VPN_PASS"
\$CertPath = Join-Path \$PSScriptRoot "server.cer"

# Импорт сертификата в доверенные (CurrentUser). Без админки.
Import-Certificate -FilePath \$CertPath -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null

# Если подключение уже есть - удалим и создадим заново (идемпотентность)
\$exists = Get-VpnConnection -Name \$VpnName -ErrorAction SilentlyContinue
if (\$exists) {
  Remove-VpnConnection -Name \$VpnName -Force
}

Add-VpnConnection -Name \$VpnName -ServerAddress \$Server -TunnelType SSTP \`
  -AuthenticationMethod MSChapv2 -EncryptionLevel Optional -Force | Out-Null

rasdial "\$VpnName" "\$User" "\$Pass"
EOF

  # Linux script: installs sstp-client and connects (credentials inline)
  cat >"$CLIENT_DIR/linux_sstp.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

SERVER="$PUBLIC_HOST"
USER="$VPN_USER"
PASS="$VPN_PASS"

# Требуется root
if [ "\${EUID:-0}" -ne 0 ]; then
  echo "Запусти: sudo \$0"
  exit 1
fi

apt-get update
apt-get install -y sstp-client ppp

# --cert-warn: отключаем строгую проверку сертификата (как ты и просил - быстро и просто)
# defaultroute: весь трафик через VPN
sstpc --cert-warn --user "\$USER" --password "\$PASS" "\$SERVER" \\
  usepeerdns require-mschap-v2 refuse-eap noipdefault defaultroute
EOF
  chmod +x "$CLIENT_DIR/linux_sstp.sh"

  cat >"$CLIENT_DIR/README.txt" <<EOF
SSTP server: $PUBLIC_HOST
Hub:         ${HUB_NAME:-VPN}
User:        $VPN_USER
Password:    $VPN_PASS

Windows:
  1) Скопируй папку softether-clients на ПК
  2) Запусти PowerShell:
     .\\windows_sstp.ps1

Linux (Debian/Ubuntu):
  sudo ./linux_sstp.sh

Android:
  Любой SSTP-клиент:
   Server: $PUBLIC_HOST
   User: $VPN_USER
   Pass: $VPN_PASS
  Если спросит про сертификат: отключи проверку или импортируй server.cer (если клиент умеет).
EOF

  (cd /root && zip -r softether-clients.zip "$(basename "$CLIENT_DIR")" >/dev/null)
  echo "Готово:"
  echo "  Папка: $CLIENT_DIR"
  echo "  Архив: /root/softether-clients.zip"
  echo "Скачать:"
  echo "  scp root@${PUBLIC_HOST}:/root/softether-clients.zip ."
}

uninstall_all() {
  need_root
  systemctl disable --now vpnserver 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload || true
  rm -rf "$VPNROOT" "$SRCDIR" "$CLIENT_DIR" /root/softether-clients.zip
  rm -f "$STATE"
  echo "Всё удалено."
}

menu() {
  cat <<'EOF'
1) Установить + настроить + создать пользователя + сгенерировать клиентские скрипты
2) Добавить пользователя
3) Удалить пользователя
4) Удалить весь сервис
EOF
  local c
  tty_read c "Выбор: "
  case "$c" in
    1) install_softether; initial_config ;;
    2) add_user ;;
    3) del_user ;;
    4) uninstall_all ;;
    *) echo "Неверный выбор." ;;
  esac
}

menu
