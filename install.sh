#!/usr/bin/env bash
set -euo pipefail

APP="SoftEther SSTP VPN Manager"
REPO="https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git"

SRC_BASE="/usr/local/src"
SRC_DIR="${SRC_BASE}/SoftEtherVPN_Stable"

INSTALL_DIR="/usr/local/vpnserver"
VPNCMD="${INSTALL_DIR}/vpncmd/vpncmd"
VPNSERVER_BIN="${INSTALL_DIR}/vpnserver/vpnserver"
VPNSERVER_WORKDIR="${INSTALL_DIR}/vpnserver"

UNIT="/etc/systemd/system/vpnserver.service"

STATE="/root/softether-sstp.env"     # тут запоминаем host/admin/hub
STATE_MODE=600

PORT="443"
DEFAULT_HUB="VPN"

TTY="/dev/tty"

log(){ echo "[$(date +'%F %T')] $*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

need_root(){ [[ "$(id -u)" -eq 0 ]] || die "Запусти от root."; }

have_tty(){ [[ -r "$TTY" && -w "$TTY" ]]; }

prompt(){
  local text="${1:-}" def="${2:-}"
  local ans=""
  have_tty || { [[ -n "$def" ]] && { echo "$def"; return 0; } || die "Нет TTY для ввода. Используй параметры."; }
  if [[ -n "$def" ]]; then printf "%s [%s]: " "$text" "$def" >"$TTY"
  else printf "%s: " "$text" >"$TTY"; fi
  IFS= read -r ans <"$TTY" || true
  [[ -n "$ans" ]] && echo "$ans" || echo "$def"
}

prompt_secret(){
  local text="${1:-}"
  local ans=""
  have_tty || die "Нет TTY для ввода. Используй параметры."
  printf "%s: " "$text" >"$TTY"
  stty -echo <"$TTY"
  IFS= read -r ans <"$TTY" || true
  stty echo <"$TTY"
  printf "\n" >"$TTY"
  echo "$ans"
}

pause(){
  have_tty || return 0
  printf "Нажми Enter..." >"$TTY"
  IFS= read -r _ <"$TTY" || true
}

detect_public_ip(){
  # best-effort, без гарантии, но обычно работает
  local ip=""
  ip="$(curl -4fsS https://api.ipify.org 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4fsS https://ifconfig.me 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4fsS https://ipinfo.io/ip 2>/dev/null || true)"
  if [[ -z "$ip" ]]; then
    # fallback: первый IPv4 на машине
    ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  fi
  echo "$ip"
}

save_state(){
  local host="$1" admin="$2" hub="$3"
  cat >"$STATE" <<EOF
HOST="$host"
ADMIN_PASS="$admin"
HUB="$hub"
PORT="$PORT"
EOF
  chmod "$STATE_MODE" "$STATE"
}

load_state(){
  [[ -f "$STATE" ]] || return 1
  # shellcheck disable=SC1090
  source "$STATE"
  [[ -n "${HOST:-}" && -n "${ADMIN_PASS:-}" && -n "${HUB:-}" ]] || return 1
  return 0
}

is_installed(){
  [[ -x "$VPNCMD" && -x "$VPNSERVER_BIN" ]]
}

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl unzip zip git \
    build-essential libreadline-dev libssl-dev zlib1g-dev \
    openssl
}

install_softether(){
  log "Ставлю SoftEther из GitHub и собираю..."
  mkdir -p "$SRC_BASE"
  rm -rf "$SRC_DIR"
  git clone --depth 1 "$REPO" "$SRC_DIR"
  cd "$SRC_DIR"
  ./configure
  make -j"$(nproc)"

  log "Устанавливаю в $INSTALL_DIR (без rsync, да, представляешь)..."
  mkdir -p "$INSTALL_DIR/vpnserver" "$INSTALL_DIR/vpncmd"
  cp -a "$SRC_DIR/bin/vpnserver/." "$INSTALL_DIR/vpnserver/"
  cp -a "$SRC_DIR/bin/vpncmd/."    "$INSTALL_DIR/vpncmd/"

  chmod 700 "$INSTALL_DIR/vpnserver/vpnserver" "$INSTALL_DIR/vpncmd/vpncmd"
}

install_unit(){
  log "Ставлю systemd unit..."
  cat >"$UNIT" <<EOF
[Unit]
Description=SoftEther VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
WorkingDirectory=$VPNSERVER_WORKDIR
ExecStart=$VPNSERVER_BIN start
ExecStop=$VPNSERVER_BIN stop
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vpnserver
}

vpncmd_blank_admin(){
  # на свежей установке пароль админа пустой, подаём пустую строку в prompt Password:
  local cmd=("$@")
  printf "\n" | "$VPNCMD" localhost /SERVER /CMD "${cmd[@]}" >/dev/null
}

vpncmd_admin(){
  local admin="$1"; shift
  local cmd=("$@")
  "$VPNCMD" localhost /SERVER /PASSWORD:"$admin" /CMD "${cmd[@]}" >/dev/null
}

vpncmd_hub(){
  local admin="$1" hub="$2"; shift 2
  local cmd=("$@")
  "$VPNCMD" localhost /SERVER /PASSWORD:"$admin" /HUB:"$hub" /CMD "${cmd[@]}" >/dev/null
}

configure_server(){
  local host="$1" admin="$2" hub="$3"

  log "Ставлю пароль администратора SoftEther (если уже стоит, просто переживём)..."
  vpncmd_blank_admin ServerPasswordSet "$admin" || true

  log "Оставляю слушатель только на TCP/$PORT (лишнее прибиваю)..."
  vpncmd_admin "$admin" ListenerCreate "$PORT" || true
  vpncmd_admin "$admin" ListenerEnable "$PORT" || true
  vpncmd_admin "$admin" ListenerDelete 992  || true
  vpncmd_admin "$admin" ListenerDelete 5555 || true
  vpncmd_admin "$admin" ListenerDelete 1194 || true

  log "Перегенерирую серверный SSL сертификат под CN=$host (чтобы Windows меньше ныл)..."
  vpncmd_admin "$admin" ServerCertRegenerate "$host" || true

  log "Создаю HUB $hub (если уже есть, ок)..."
  # HUB пароль не спрашиваем вообще, он не нужен для твоего сценария "просто интернет"
  vpncmd_admin "$admin" HubCreate "$hub" /PASSWORD:"$admin" || true

  log "Включаю SecureNAT на HUB (выход в интернет)..."
  vpncmd_hub "$admin" "$hub" SecureNatEnable || true

  log "Включаю SSTP..."
  vpncmd_admin "$admin" SstpEnable yes || true

  systemctl restart vpnserver
  systemctl is-active --quiet vpnserver || die "vpnserver не запустился. Смотри: journalctl -u vpnserver -n 200 --no-pager"
}

create_user(){
  local admin="$1" hub="$2" user="$3" pass="$4"
  log "Создаю/обновляю пользователя $user в HUB $hub..."
  vpncmd_hub "$admin" "$hub" UserCreate "$user" /GROUP:none /REALNAME:none /NOTE:none || true
  vpncmd_hub "$admin" "$hub" UserPasswordSet "$user" /PASSWORD:"$pass"
}

delete_user(){
  local admin="$1" hub="$2" user="$3"
  log "Удаляю пользователя $user..."
  vpncmd_hub "$admin" "$hub" UserDelete "$user" || true
}

export_server_cert(){
  local host="$1" pem="$2" der="$3"
  log "Снимаю сертификат с $host:$PORT ..."
  openssl s_client -connect "${host}:${PORT}" -servername "$host" -showcerts </dev/null 2>/dev/null \
    | awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c++} c==1{print} /END CERTIFICATE/{if(c==1) exit}' \
    >"$pem"
  openssl x509 -in "$pem" -outform DER -out "$der"
}

gen_clients(){
  local host="$1" hub="$2" user="$3" pass="$4"

  local out_dir="/root/${user}_clients"
  local zip_path="/root/${host}_${user}_clients.zip"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  chmod 700 "$out_dir"

  export_server_cert "$host" "$out_dir/server-cert.pem" "$out_dir/server.cer"

  local vpn_name="SSTP-${host}"

  cat >"$out_dir/windows_connect.ps1" <<EOF
# Требуются права администратора (импорт сертификата в LocalMachine\\Root)
\$ErrorActionPreference = "Stop"

\$Server = "$host"
\$Hub    = "$hub"
\$User   = "${user}@${hub}"
\$Pass   = "$pass"
\$Name   = "$vpn_name"

\$certPath = Join-Path \$PSScriptRoot "server.cer"
if (-not (Test-Path \$certPath)) { throw "Не найден server.cer рядом со скриптом" }

Write-Host "Импорт сертификата в Trusted Root (LocalMachine)..."
Import-Certificate -FilePath \$certPath -CertStoreLocation "Cert:\\LocalMachine\\Root" | Out-Null

Write-Host "Создаю VPN-подключение: \$Name -> \$Server (SSTP)..."
\$existing = Get-VpnConnection -Name \$Name -ErrorAction SilentlyContinue
if (\$existing) { Remove-VpnConnection -Name \$Name -Force | Out-Null }

Add-VpnConnection -Name \$Name -ServerAddress \$Server -TunnelType SSTP -EncryptionLevel Optional -AuthenticationMethod MSChapv2 -SplitTunneling \$false -Force | Out-Null

Write-Host "Подключаюсь..."
rasdial "\$Name" "\$User" "\$Pass" | Out-Host
EOF

  cat >"$out_dir/windows_disconnect.ps1" <<EOF
\$ErrorActionPreference = "Stop"
rasdial "$vpn_name" /DISCONNECT | Out-Host
EOF

  cat >"$out_dir/windows_run_as_admin.bat" <<'EOF'
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows_connect.ps1"
EOF

  cat >"$out_dir/linux_connect.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

SERVER="$host"
USER="${user}@${hub}"
PASS="$pass"

sudo apt-get update -y
sudo apt-get install -y sstp-client ppp

# безопасность пофиг, как просили:
sudo sstpc --cert-warn --tls-ext --user "\$USER" --password "\$PASS" "\$SERVER" usepeerdns require-mschap-v2 noauth noccp defaultroute &
echo "OK. Отключение: ./linux_disconnect.sh"
EOF
  chmod +x "$out_dir/linux_connect.sh"

  cat >"$out_dir/linux_disconnect.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
sudo pkill -f 'sstpc' || true
echo "Отключено."
EOF
  chmod +x "$out_dir/linux_disconnect.sh"

  cat >"$out_dir/README.txt" <<EOF
Сервер: $host:$PORT
HUB:    $hub
Логин:  ${user}@${hub}

Windows:
- скопируй папку ${user}_clients на ПК
- запусти windows_run_as_admin.bat от имени администратора

Linux (Debian/Ubuntu):
- ./linux_connect.sh
- отключить: ./linux_disconnect.sh

Android:
- любой SSTP-клиент
  Server: $host
  User:   ${user}@${hub}
  Pass:   (как выдал скрипт)
EOF

  (cd /root && zip -r -9 "$(basename "$zip_path")" "$(basename "$out_dir")" >/dev/null)

  log "Готово. Клиенты в:"
  log "  $out_dir"
  log "  $zip_path"
}

purge_all(){
  log "Останавливаю сервис..."
  systemctl disable --now vpnserver 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload || true

  log "Удаляю установленный SoftEther..."
  rm -rf "$INSTALL_DIR"

  log "Удаляю исходники сборки..."
  rm -rf "$SRC_DIR"

  log "Удаляю state и клиентские файлы из /root..."
  rm -f "$STATE"
  rm -rf /root/*_clients 2>/dev/null || true
  rm -f /root/*_clients.zip 2>/dev/null || true

  log "Готово. Всё удалено."
}

do_install_flow(){
  local detected host admin hub user pass

  detected="$(detect_public_ip)"
  [[ -n "$detected" ]] || detected="(не смог определить)"
  host="$(prompt "IP/DNS сервера (Enter = авто)" "${detected}")"
  [[ -n "$host" && "$host" != "(не смог определить)" ]] || die "Нужен IP/DNS (авто-детект не сработал)."

  admin="$(prompt_secret "Пароль администратора SoftEther (запомню, больше не спрошу)")"
  [[ -n "$admin" ]] || die "Пустой admin пароль не нужен даже тебе."

  hub="$(prompt "Имя HUB" "$DEFAULT_HUB")"
  [[ -n "$hub" ]] || hub="$DEFAULT_HUB"

  user="$(prompt "Логин пользователя" "vpn")"
  pass="$(prompt_secret "Пароль пользователя")"
  [[ -n "$pass" ]] || die "Пустой пароль пользователя? Ну ты понял."

  apt_install
  install_softether
  install_unit
  configure_server "$host" "$admin" "$hub"
  save_state "$host" "$admin" "$hub"
  create_user "$admin" "$hub" "$user" "$pass"
  gen_clients "$host" "$hub" "$user" "$pass"

  cat >"$TTY" <<EOF

=== Дальше что делать ===
1) Забери архив с сервера:
   /root/${host}_${user}_clients.zip

2) Windows:
   - распакуй
   - запусти windows_run_as_admin.bat (от админа)

3) Linux:
   - ./linux_connect.sh

EOF
  pause
}

do_add_user_flow(){
  load_state || die "Нет $STATE. Сначала пункт 1 (установка)."
  is_installed || die "SoftEther не установлен. Сначала пункт 1."

  local user pass
  user="$(prompt "Логин пользователя" "vpn")"
  pass="$(prompt_secret "Пароль пользователя")"
  [[ -n "$pass" ]] || die "Пустой пароль пользователя."

  create_user "$ADMIN_PASS" "$HUB" "$user" "$pass"
  gen_clients "$HOST" "$HUB" "$user" "$pass"
  pause
}

do_del_user_flow(){
  load_state || die "Нет $STATE. Сначала пункт 1 (установка)."
  is_installed || die "SoftEther не установлен."

  local user
  user="$(prompt "Логин пользователя на удаление" "")"
  [[ -n "$user" ]] || die "Нужен логин."

  delete_user "$ADMIN_PASS" "$HUB" "$user"
  rm -rf "/root/${user}_clients" 2>/dev/null || true
  rm -f "/root/${HOST}_${user}_clients.zip" 2>/dev/null || true
  log "Удалено."
  pause
}

menu(){
  while true; do
    cat >"$TTY" <<EOF

$APP
1) Установить/настроить сервер + создать пользователя + сгенерировать клиенты
2) Добавить пользователя (и сгенерировать клиенты)
3) Удалить пользователя
4) Удалить весь сервис
0) Выход

EOF
    local c
    c="$(prompt "Выбор" "")"
    case "$c" in
      1) do_install_flow ;;
      2) do_add_user_flow ;;
      3) do_del_user_flow ;;
      4)
        local sure
        sure="$(prompt "Точно удалить ВСЁ? (yes/no)" "no")"
        [[ "$sure" == "yes" ]] || { log "Отменено."; pause; continue; }
        purge_all
        pause
        ;;
      0) exit 0 ;;
      *) log "Неверный выбор."; pause ;;
    esac
  done
}

need_root
have_tty || die "Запусти в нормальном терминале (нужен /dev/tty)."
menu
