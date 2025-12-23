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

STATE="/root/softether-sstp.env"
STATE_MODE=600

PORT_DEFAULT="443"
HUB_DEFAULT="VPN"

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

is_installed(){
  [[ -x "$VPNCMD" && -x "$VPNSERVER_BIN" ]]
}

load_state(){
  [[ -f "$STATE" ]] || return 1
  # shellcheck disable=SC1090
  source "$STATE"
  [[ -n "${HOST:-}" && -n "${ADMIN_PASS:-}" && -n "${HUB:-}" && -n "${PORT:-}" ]] || return 1
  return 0
}

save_state(){
  local host="$1" admin="$2" hub="$3" port="$4"
  cat >"$STATE" <<EOF
HOST="$host"
ADMIN_PASS="$admin"
HUB="$hub"
PORT="$port"
EOF
  chmod "$STATE_MODE" "$STATE"
}

detect_public_ip(){
  local ip=""
  ip="$(curl -4fsS https://api.ipify.org 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4fsS https://ifconfig.me 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4fsS https://ipinfo.io/ip 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(ip -4 addr show | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  echo "$ip"
}

port_owner(){
  local port="$1"
  ss -lntp "sport = :$port" 2>/dev/null | tail -n +2 | sed -n '1p' || true
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

  log "Устанавливаю в $INSTALL_DIR ..."
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

# ---- vpncmd wrappers (важно: подаём "y", чтобы не зависало на подтверждениях) ----
vpncmd_raw(){
  # $1 = stdin text (может быть пустым)
  local stdin_text="${1:-}"; shift
  if [[ -n "$stdin_text" ]]; then
    printf "%b" "$stdin_text" | "$VPNCMD" "$@"
  else
    "$VPNCMD" "$@"
  fi
}

vpncmd_try(){
  # returns 0 if command works (no hang, no fatal)
  local stdin_text="${1:-}"; shift
  vpncmd_raw "$stdin_text" "$@" >/dev/null 2>&1
}

vpncmd_blank_admin(){
  # admin password is empty (fresh install). Send newline for "Password:" prompt + y just in case.
  vpncmd_raw "\n" localhost /SERVER /CMD "$@" >/dev/null
}

vpncmd_admin(){
  local admin="$1"; shift
  # send "y\n" just in case some command asks confirmation
  vpncmd_raw "y\n" localhost /SERVER /PASSWORD:"$admin" /CMD "$@" >/dev/null
}

vpncmd_hub(){
  local admin="$1" hub="$2"; shift 2
  vpncmd_raw "y\n" localhost /SERVER /PASSWORD:"$admin" /HUB:"$hub" /CMD "$@" >/dev/null
}

ensure_admin_password(){
  local admin="$1"
  # Case A: fresh install, blank password
  if vpncmd_try "\n" localhost /SERVER /CMD ServerInfoGet; then
    vpncmd_blank_admin ServerPasswordSet "$admin"
    return 0
  fi
  # Case B: password already set, try provided one
  if vpncmd_try "" localhost /SERVER /PASSWORD:"$admin" /CMD ServerInfoGet; then
    return 0
  fi
  die "Не могу авторизоваться в vpncmd. Пароль администратора неверный или сервер не доступен."
}

configure_server(){
  local host="$1" admin="$2" hub="$3" port="$4"

  log "Ставлю/проверяю пароль администратора SoftEther..."
  ensure_admin_password "$admin"

  log "Проверяю порт $port..."
  local owner
  owner="$(port_owner "$port")"
  if [[ -n "$owner" && "$owner" != *vpnserver* ]]; then
    die "Порт $port занят: $owner. Освободи порт или выбери другой."
  fi

  log "Настраиваю слушатель $port (disable лишнее, enable нужное)..."
  # Не удаляем listener'ы (там могут быть подтверждения/подвисы), просто выключаем.
  vpncmd_admin "$admin" ListenerCreate "$port" || true
  vpncmd_admin "$admin" ListenerEnable "$port" || true

  # попытка отключить стандартные порты (если есть) без боли
  vpncmd_admin "$admin" ListenerDisable 992  || true
  vpncmd_admin "$admin" ListenerDisable 5555 || true
  vpncmd_admin "$admin" ListenerDisable 1194 || true

  log "Перегенерирую серверный SSL сертификат под CN=$host ..."
  vpncmd_admin "$admin" ServerCertRegenerate "$host" || true

  log "Создаю HUB $hub (если уже есть, ок)..."
  vpncmd_admin "$admin" HubCreate "$hub" /PASSWORD:"$admin" || true

  log "Включаю SecureNAT (выход в интернет)..."
  vpncmd_hub "$admin" "$hub" SecureNatEnable || true

  log "Включаю SSTP..."
  vpncmd_admin "$admin" SstpEnable yes || true

  systemctl restart vpnserver
  systemctl is-active --quiet vpnserver || die "vpnserver не запустился. journalctl -u vpnserver -n 200 --no-pager"
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

export_server_cert_local(){
  # Берём сертификат с localhost, чтобы не зависеть от внешней сети/маршрутизации.
  local sni="$1" port="$2" pem="$3" der="$4"
  log "Снимаю сертификат с 127.0.0.1:$port (SNI=$sni)..."
  openssl s_client -connect "127.0.0.1:${port}" -servername "$sni" -showcerts </dev/null 2>/dev/null \
    | awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c++} c==1{print} /END CERTIFICATE/{if(c==1) exit}' \
    >"$pem"
  openssl x509 -in "$pem" -outform DER -out "$der"
}

gen_clients(){
  local host="$1" hub="$2" user="$3" pass="$4" port="$5"

  local out_dir="/root/${user}_clients"
  local zip_path="/root/${host}_${user}_clients.zip"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  chmod 700 "$out_dir"

  export_server_cert_local "$host" "$port" "$out_dir/server-cert.pem" "$out_dir/server.cer"

  local vpn_name="SSTP-${host}"

  cat >"$out_dir/windows_connect.ps1" <<EOF
# Требуются права администратора (импорт сертификата в LocalMachine\\Root)
\$ErrorActionPreference = "Stop"

\$Server = "$host"
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

# безопасность "как попросили":
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
Сервер: $host:$port
HUB:    $hub
Логин:  ${user}@${hub}

Готовые файлы подключения:
- Windows: windows_run_as_admin.bat (запуск от администратора)
- Linux:   linux_connect.sh

Android:
- любой SSTP-клиент
  Server: $host
  User:   ${user}@${hub}
  Pass:   (как задано)
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

usage(){
  cat <<EOF
$APP

Интерактивно:
  curl -fsSL https://raw.githubusercontent.com/igruli0807/sstp-vpn/main/install.sh | bash

Быстрый режим:
  bash install.sh --install --host X.X.X.X --adminpass ADMIN --hub VPN --user vpn --pass PASS [--port 443]
  bash install.sh --add-user --user NAME --pass PASS
  bash install.sh --del-user --user NAME
  bash install.sh --purge
EOF
}

# ---- flows ----
do_install_flow(){
  local host admin hub user pass port detected

  detected="$(detect_public_ip)"
  port="$PORT_DEFAULT"
  hub="$HUB_DEFAULT"

  if have_tty; then
    host="$(prompt "IP/DNS сервера (Enter = авто)" "$detected")"
    [[ -n "$host" ]] || die "Нужен IP/DNS."
    port="$(prompt "Порт" "$port")"
    admin="$(prompt_secret "Пароль администратора SoftEther (запомню)")"
    [[ -n "$admin" ]] || die "Пустой admin пароль не нужен."
    hub="$(prompt "Имя HUB" "$hub")"
    user="$(prompt "Логин пользователя" "vpn")"
    pass="$(prompt_secret "Пароль пользователя")"
    [[ -n "$pass" ]] || die "Пустой пароль пользователя."
  else
    die "Нет TTY. Используй параметры --install ..."
  fi

  # если уже установлено: не пересобираем, просто продолжаем
  if ! is_installed; then
    apt_install
    install_softether
    install_unit
  else
    log "SoftEther уже установлен, пересборку пропускаю."
    systemctl enable --now vpnserver || true
  fi

  configure_server "$host" "$admin" "$hub" "$port"
  save_state "$host" "$admin" "$hub" "$port"
  create_user "$admin" "$hub" "$user" "$pass"
  gen_clients "$host" "$hub" "$user" "$pass" "$port"

  cat >"$TTY" <<EOF

=== Дальше что делать ===
1) Забери архив:
   /root/${host}_${user}_clients.zip

2) Windows:
   - распакуй архив
   - запусти windows_run_as_admin.bat (от имени администратора)

3) Linux:
   - ./linux_connect.sh
   - отключить: ./linux_disconnect.sh

EOF
  pause
}

do_add_user_flow(){
  load_state || die "Нет $STATE. Сначала установка (пункт 1) или --install."
  is_installed || die "SoftEther не установлен. Сначала установка (пункт 1)."

  local user pass
  if have_tty; then
    user="$(prompt "Логин пользователя" "vpn")"
    pass="$(prompt_secret "Пароль пользователя")"
  else
    die "Нет TTY. Используй --add-user --user ... --pass ..."
  fi

  [[ -n "$pass" ]] || die "Пустой пароль пользователя."
  create_user "$ADMIN_PASS" "$HUB" "$user" "$pass"
  gen_clients "$HOST" "$HUB" "$user" "$pass" "$PORT"
  pause
}

do_del_user_flow(){
  load_state || die "Нет $STATE. Сначала установка."
  is_installed || die "SoftEther не установлен."

  local user
  if have_tty; then
    user="$(prompt "Логин пользователя на удаление" "")"
  else
    die "Нет TTY. Используй --del-user --user ..."
  fi
  [[ -n "$user" ]] || die "Нужен логин."

  delete_user "$ADMIN_PASS" "$HUB" "$user"
  rm -rf "/root/${user}_clients" 2>/dev/null || true
  rm -f "/root/${HOST}_${user}_clients.zip" 2>/dev/null || true
  log "Удалено."
  pause
}

# ---- CLI args ----
MODE=""
HOST_ARG="" ADMIN_ARG="" HUB_ARG="" USER_ARG="" PASS_ARG="" PORT_ARG="$PORT_DEFAULT"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) MODE="install"; shift;;
    --add-user) MODE="add"; shift;;
    --del-user) MODE="del"; shift;;
    --purge) MODE="purge"; shift;;
    --host) HOST_ARG="${2:-}"; shift 2;;
    --adminpass) ADMIN_ARG="${2:-}"; shift 2;;
    --hub) HUB_ARG="${2:-}"; shift 2;;
    --user) USER_ARG="${2:-}"; shift 2;;
    --pass) PASS_ARG="${2:-}"; shift 2;;
    --port) PORT_ARG="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) die "Неизвестный аргумент: $1";;
  esac
done

need_root

if [[ -n "$MODE" ]]; then
  case "$MODE" in
    purge)
      purge_all
      exit 0
      ;;
    install)
      [[ -n "$HOST_ARG" && -n "$ADMIN_ARG" && -n "$USER_ARG" && -n "$PASS_ARG" ]] || die "Нужны --host --adminpass --user --pass (и опционально --hub --port)"
      [[ -n "$HUB_ARG" ]] || HUB_ARG="$HUB_DEFAULT"
      [[ -n "$PORT_ARG" ]] || PORT_ARG="$PORT_DEFAULT"

      if ! is_installed; then
        apt_install
        install_softether
        install_unit
      else
        log "SoftEther уже установлен, пересборку пропускаю."
        systemctl enable --now vpnserver || true
      fi

      configure_server "$HOST_ARG" "$ADMIN_ARG" "$HUB_ARG" "$PORT_ARG"
      save_state "$HOST_ARG" "$ADMIN_ARG" "$HUB_ARG" "$PORT_ARG"
      create_user "$ADMIN_ARG" "$HUB_ARG" "$USER_ARG" "$PASS_ARG"
      gen_clients "$HOST_ARG" "$HUB_ARG" "$USER_ARG" "$PASS_ARG" "$PORT_ARG"
      exit 0
      ;;
    add)
      load_state || die "Нет $STATE. Сначала --install."
      is_installed || die "SoftEther не установлен."
      [[ -n "$USER_ARG" && -n "$PASS_ARG" ]] || die "Нужны --user --pass"
      create_user "$ADMIN_PASS" "$HUB" "$USER_ARG" "$PASS_ARG"
      gen_clients "$HOST" "$HUB" "$USER_ARG" "$PASS_ARG" "$PORT"
      exit 0
      ;;
    del)
      load_state || die "Нет $STATE. Сначала --install."
      is_installed || die "SoftEther не установлен."
      [[ -n "$USER_ARG" ]] || die "Нужен --user"
      delete_user "$ADMIN_PASS" "$HUB" "$USER_ARG"
      rm -rf "/root/${USER_ARG}_clients" 2>/dev/null || true
      rm -f "/root/${HOST}_${USER_ARG}_clients.zip" 2>/dev/null || true
      exit 0
      ;;
  esac
fi

# ---- Interactive menu ----
have_tty || die "Нет TTY. Для неинтерактива используй параметры (--install/--add-user/...)."

while true; do
  cat >"$TTY" <<EOF

$APP
1) Установить/настроить сервер + создать пользователя + сгенерировать клиенты
2) Добавить пользователя (и сгенерировать клиенты)
3) Удалить пользователя
4) Удалить весь сервис
0) Выход

EOF
  c="$(prompt "Выбор" "")"
  case "$c" in
    1) do_install_flow ;;
    2) do_add_user_flow ;;
    3) do_del_user_flow ;;
    4)
      sure="$(prompt "Точно удалить ВСЁ? (yes/no)" "no")"
      [[ "$sure" == "yes" ]] || { log "Отменено."; pause; continue; }
      purge_all
      pause
      ;;
    0) exit 0 ;;
    *) log "Неверный выбор."; pause ;;
  esac
done
