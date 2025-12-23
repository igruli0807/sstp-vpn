#!/usr/bin/env bash
set -euo pipefail

APP_NAME="SoftEther SSTP VPN Manager"
BASE_DIR="/root/sstp-vpn"
CLIENTS_DIR="$BASE_DIR/clients"

SOFTETHER_ROOT="/usr/local/vpnserver"
VPNCMD="$SOFTETHER_ROOT/vpncmd/vpncmd"
VPNSERVER_BIN="$SOFTETHER_ROOT/vpnserver/vpnserver"
VPNSERVER_WORKDIR="$SOFTETHER_ROOT/vpnserver"

SYSTEMD_UNIT="/etc/systemd/system/vpnserver.service"

DEFAULT_HUB="VPN"
LISTEN_PORT="443"

TTY_DEV="/dev/tty"

log() { echo -e "[$(date +'%F %T')] $*"; }
die() { echo -e "ERROR: $*" >&2; exit 1; }

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Запусти от root."
}

have_tty() {
  [[ -r "$TTY_DEV" && -w "$TTY_DEV" ]]
}

prompt() {
  # prompt "Text" "default" -> echoes result
  local text="${1:-}"
  local def="${2:-}"
  local ans=""
  if ! have_tty; then
    [[ -n "$def" ]] && { echo "$def"; return 0; }
    die "Нет TTY (ввод невозможен). Используй параметры командной строки."
  fi
  if [[ -n "$def" ]]; then
    printf "%s [%s]: " "$text" "$def" >"$TTY_DEV"
  else
    printf "%s: " "$text" >"$TTY_DEV"
  fi
  IFS= read -r ans <"$TTY_DEV" || true
  if [[ -z "$ans" ]]; then
    echo "$def"
  else
    echo "$ans"
  fi
}

prompt_secret() {
  # prompt_secret "Text" -> echoes result
  local text="${1:-}"
  local ans=""
  if ! have_tty; then
    die "Нет TTY (ввод невозможен). Используй параметры командной строки."
  fi
  printf "%s: " "$text" >"$TTY_DEV"
  stty -echo <"$TTY_DEV"
  IFS= read -r ans <"$TTY_DEV" || true
  stty echo <"$TTY_DEV"
  printf "\n" >"$TTY_DEV"
  echo "$ans"
}

pause() {
  have_tty || return 0
  printf "Нажми Enter..." >"$TTY_DEV"
  IFS= read -r _ <"$TTY_DEV" || true
}

ensure_dirs() {
  mkdir -p "$BASE_DIR" "$CLIENTS_DIR"
  chmod 700 "$BASE_DIR" "$CLIENTS_DIR"
}

install_deps() {
  log "Ставлю зависимости..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl unzip zip git \
    build-essential libreadline-dev libssl-dev zlib1g-dev \
    openssl
}

install_softether() {
  if [[ -x "$VPNCMD" && -x "$VPNSERVER_BIN" ]]; then
    log "SoftEther уже установлен: $SOFTETHER_ROOT"
    return 0
  fi

  log "Ставлю SoftEther из GitHub (SoftEtherVPN_Stable) и собираю..."
  mkdir -p /usr/local/src
  cd /usr/local/src

  if [[ -d /usr/local/src/SoftEtherVPN_Stable ]]; then
    rm -rf /usr/local/src/SoftEtherVPN_Stable
  fi

  git clone --depth 1 https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git
  cd SoftEtherVPN_Stable

  ./configure
  make -j"$(nproc)"

  log "Устанавливаю в $SOFTETHER_ROOT ..."
  mkdir -p "$SOFTETHER_ROOT"
  rsync -a --delete ./bin/vpnserver/ "$SOFTETHER_ROOT/vpnserver/"
  rsync -a --delete ./bin/vpncmd/ "$SOFTETHER_ROOT/vpncmd/"

  chmod 700 "$SOFTETHER_ROOT/vpnserver/vpnserver" "$SOFTETHER_ROOT/vpncmd/vpncmd"
}

install_systemd_unit() {
  log "Ставлю systemd unit..."
  cat >"$SYSTEMD_UNIT" <<EOF
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

vpncmd_server_no_pass() {
  # For a fresh server (blank admin password): feed blank line for "Password:" prompt if it appears.
  # Usage: vpncmd_server_no_pass "Command ..." (single string)
  local cmd="$1"
  printf "\n" | "$VPNCMD" localhost /SERVER /CMD $cmd >/dev/null
}

vpncmd_server() {
  # Usage: vpncmd_server "$ADMIN_PASS" "Command ..."
  local admin_pass="$1"
  local cmd="$2"
  "$VPNCMD" localhost /SERVER /PASSWORD:"$admin_pass" /CMD $cmd >/dev/null
}

vpncmd_hub() {
  # Usage: vpncmd_hub "$ADMIN_PASS" "$HUB" "Command ..."
  local admin_pass="$1"
  local hub="$2"
  local cmd="$3"
  "$VPNCMD" localhost /SERVER /PASSWORD:"$admin_pass" /HUB:"$hub" /CMD $cmd >/dev/null
}

configure_softether_minimal_sstp() {
  # Args: host admin_pass hub hub_pass
  local host="$1"
  local admin_pass="$2"
  local hub="$3"
  local hub_pass="$4"

  log "Останавливаю возможный OpenVPN-сервис (если был), чтобы не мешал портам..."
  systemctl disable --now openvpn-server@server 2>/dev/null || true
  systemctl disable --now openvpn@server 2>/dev/null || true
  systemctl disable --now openvpn 2>/dev/null || true

  log "Ставлю пароль администратора SoftEther VPN Server..."
  # On a fresh server admin password is blank: connect without /PASSWORD and run ServerPasswordSet
  vpncmd_server_no_pass "ServerPasswordSet $admin_pass" || true

  log "Генерирую новый SSL-сертификат сервера с CN=$host (чтобы SSTP на Windows не падал по name mismatch)..."
  # ServerCertRegenerate <CN>
  vpncmd_server "$admin_pass" "ServerCertRegenerate $host" || true

  log "Оставляю слушатель только на TCP/$LISTEN_PORT (режу лишние порты: 992, 5555, 1194)..."
  vpncmd_server "$admin_pass" "ListenerCreate $LISTEN_PORT" || true
  vpncmd_server "$admin_pass" "ListenerEnable $LISTEN_PORT" || true
  vpncmd_server "$admin_pass" "ListenerDelete 992" || true
  vpncmd_server "$admin_pass" "ListenerDelete 5555" || true
  vpncmd_server "$admin_pass" "ListenerDelete 1194" || true

  log "Создаю (или оставляю) HUB '$hub'..."
  vpncmd_server "$admin_pass" "HubCreate $hub /PASSWORD:$hub_pass" || true

  log "Задаю пароль HUB '$hub'..."
  # SetHubPassword is executed in hub context
  vpncmd_hub "$admin_pass" "$hub" "SetHubPassword /PASSWORD:$hub_pass" || true

  log "Включаю SecureNAT (интернет через VPN, без построения L2/L3 сети)..."
  vpncmd_hub "$admin_pass" "$hub" "SecureNatEnable" || true

  log "Включаю SSTP..."
  # Some builds accept server-context, some hub-context. Try both.
  if ! vpncmd_server "$admin_pass" "SstpEnable yes" 2>/dev/null; then
    vpncmd_hub "$admin_pass" "$hub" "SstpEnable yes" || true
  fi

  log "Перезапускаю vpnserver..."
  systemctl restart vpnserver

  log "Проверка: сервис активен?"
  systemctl is-active --quiet vpnserver || die "vpnserver не запустился. Смотри: journalctl -u vpnserver -n 200 --no-pager"
}

create_or_update_user() {
  # Args: admin_pass hub username password
  local admin_pass="$1"
  local hub="$2"
  local user="$3"
  local pass="$4"

  log "Создаю пользователя '$user' в HUB '$hub' (если уже есть, просто обновлю пароль)..."
  vpncmd_hub "$admin_pass" "$hub" "UserCreate $user /GROUP:none /REALNAME:none /NOTE:none" || true
  vpncmd_hub "$admin_pass" "$hub" "UserPasswordSet $user /PASSWORD:$pass"
}

delete_user() {
  # Args: admin_pass hub username
  local admin_pass="$1"
  local hub="$2"
  local user="$3"

  log "Удаляю пользователя '$user' из HUB '$hub'..."
  vpncmd_hub "$admin_pass" "$hub" "UserDelete $user" || true
}

export_server_cert() {
  # Args: host out_pem out_der
  local host="$1"
  local out_pem="$2"
  local out_der="$3"

  # Extract leaf cert from TLS handshake
  # (для self-signed это и есть корневой, Windows можно закинуть в Trusted Root)
  log "Снимаю сертификат с $host:$LISTEN_PORT ..."
  openssl s_client -connect "${host}:${LISTEN_PORT}" -servername "$host" -showcerts </dev/null 2>/dev/null \
    | awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c++} c==1{print} /END CERTIFICATE/{if(c==1) exit}' \
    >"$out_pem"

  openssl x509 -in "$out_pem" -outform DER -out "$out_der"
}

gen_windows_scripts() {
  # Args: out_dir host hub user pass
  local out_dir="$1"
  local host="$2"
  local hub="$3"
  local user="$4"
  local pass="$5"

  local vpn_name="SSTP-${host}"

  cat >"$out_dir/windows_connect.ps1" <<EOF
# Требуются права администратора (импорт в LocalMachine\\Root)
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

Write-Host "Создаю/обновляю VPN-подключение: \$Name -> \$Server (SSTP)..."
\$existing = Get-VpnConnection -Name \$Name -ErrorAction SilentlyContinue
if (\$existing) {
  Remove-VpnConnection -Name \$Name -Force -ErrorAction SilentlyContinue | Out-Null
}

Add-VpnConnection -Name \$Name -ServerAddress \$Server -TunnelType SSTP -EncryptionLevel Optional -AuthenticationMethod MSChapv2 -SplitTunneling \$false -RememberCredential \$false -Force | Out-Null

Write-Host "Подключаюсь..."
rasdial "\$Name" "\$User" "\$Pass" | Out-Host

Write-Host "Готово. Чтобы отключиться: .\\windows_disconnect.ps1"
EOF

  cat >"$out_dir/windows_disconnect.ps1" <<EOF
\$ErrorActionPreference = "Stop"
\$Name = "$vpn_name"
rasdial "\$Name" /DISCONNECT | Out-Host
EOF

  cat >"$out_dir/windows_run_as_admin.bat" <<'EOF'
@echo off
REM Запусти этот .bat от имени администратора
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows_connect.ps1"
EOF
}

gen_linux_scripts() {
  # Args: out_dir host hub user pass
  local out_dir="$1"
  local host="$2"
  local hub="$3"
  local user="$4"
  local pass="$5"

  cat >"$out_dir/linux_connect.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

SERVER="$host"
USER="${user}@${hub}"
PASS="$pass"

echo "[*] Установка клиента SSTP (Debian/Ubuntu): sstp-client + ppp"
sudo apt-get update -y
sudo apt-get install -y sstp-client ppp

echo "[*] Подключение SSTP (весь трафик через VPN)..."
# --cert-warn: не ругаться на self-signed (ты сам просил «безопасность можно забить»)
sudo sstpc --cert-warn --tls-ext --user "\$USER" --password "\$PASS" "\$SERVER" usepeerdns require-mschap-v2 noauth noccp defaultroute &
echo "[*] Готово. Отключение: ./linux_disconnect.sh"
EOF
  chmod +x "$out_dir/linux_connect.sh"

  cat >"$out_dir/linux_disconnect.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
sudo pkill -f 'sstpc' || true
echo "[*] Отключено (sstpc остановлен)."
EOF
  chmod +x "$out_dir/linux_disconnect.sh"
}

write_client_readme() {
  # Args: out_dir host hub user
  local out_dir="$1"
  local host="$2"
  local hub="$3"
  local user="$4"

  cat >"$out_dir/README-CLIENT.txt" <<EOF
SSTP VPN (SoftEther) клиентские файлы

Сервер: $host:$LISTEN_PORT
HUB:    $hub
Логин:  ${user}@${hub}

Windows (встроенный SSTP):
1) Скопируй папку целиком на Windows.
2) Запусти windows_run_as_admin.bat от имени администратора.
   (он импортирует server.cer в Trusted Root и подключится)

Linux (Debian/Ubuntu):
1) ./linux_connect.sh
2) Отключить: ./linux_disconnect.sh

Android:
Нужен SSTP-клиент (например “SSTP Client” из маркета).
Сервер: $host
Тип: SSTP
Логин: ${user}@${hub}
Пароль: тот, что выдал скрипт
EOF
}

generate_clients_bundle() {
  # Args: host hub user pass
  local host="$1"
  local hub="$2"
  local user="$3"
  local pass="$4"

  ensure_dirs

  local out_dir="$CLIENTS_DIR/$user"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"
  chmod 700 "$out_dir"

  export_server_cert "$host" "$out_dir/server-cert.pem" "$out_dir/server.cer"
  gen_windows_scripts "$out_dir" "$host" "$hub" "$user" "$pass"
  gen_linux_scripts "$out_dir" "$host" "$hub" "$user" "$pass"
  write_client_readme "$out_dir" "$host" "$hub" "$user"

  local zip_path="$CLIENTS_DIR/${host}_${user}_clients.zip"
  (cd "$CLIENTS_DIR" && zip -r -9 "$(basename "$zip_path")" "$user" >/dev/null)

  log "Клиентские файлы:"
  log "  Папка: $out_dir"
  log "  Архив: $zip_path"
}

purge_all() {
  log "Останавливаю сервис..."
  systemctl disable --now vpnserver 2>/dev/null || true

  log "Удаляю systemd unit..."
  rm -f "$SYSTEMD_UNIT"
  systemctl daemon-reload || true

  log "Удаляю файлы SoftEther..."
  rm -rf "$SOFTETHER_ROOT"

  log "Удаляю рабочие файлы ($BASE_DIR)..."
  rm -rf "$BASE_DIR"

  log "Готово. Всё удалено."
}

usage() {
  cat <<EOF
$APP_NAME

Интерактивно:
  curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/install.sh | bash

Быстро (без вопросов):
  curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/install.sh | bash -s -- \\
    --install --host <IP_or_DNS> --admin-pass <pass> --hub VPN --hub-pass <pass> --user <login> --user-pass <pass>

Команды:
  --install
  --add-user
  --del-user
  --purge

Параметры:
  --host <IP/DNS>
  --admin-pass <pass>
  --hub <name>        (default: VPN)
  --hub-pass <pass>
  --user <login>
  --user-pass <pass>
EOF
}

main_menu() {
  while true; do
    cat >"$TTY_DEV" <<EOF

$APP_NAME
1) Установить/настроить сервер + создать пользователя + сгенерировать клиенты
2) Добавить пользователя (и сгенерировать клиенты)
3) Удалить пользователя
4) Удалить весь сервис
0) Выход

EOF
    local choice
    choice="$(prompt "Выбор" "")"

    case "$choice" in
      1)
        local host admin_pass hub hub_pass user user_pass
        host="$(prompt "IP или DNS сервера (CN сертификата)" "")"
        [[ -n "$host" ]] || die "Нужен host (IP/DNS)."

        admin_pass="$(prompt_secret "Пароль администратора SoftEther (ServerPassword)")"
        [[ -n "$admin_pass" ]] || die "Пароль администратора пустой."

        hub="$(prompt "Имя HUB" "$DEFAULT_HUB")"
        hub_pass="$(prompt_secret "Пароль HUB (можно любой)")"
        [[ -n "$hub_pass" ]] || hub_pass="$admin_pass"

        user="$(prompt "Логин пользователя" "vpn")"
        user_pass="$(prompt_secret "Пароль пользователя")"
        [[ -n "$user_pass" ]] || die "Пароль пользователя пустой."

        install_deps
        install_softether
        install_systemd_unit
        configure_softether_minimal_sstp "$host" "$admin_pass" "$hub" "$hub_pass"
        create_or_update_user "$admin_pass" "$hub" "$user" "$user_pass"
        generate_clients_bundle "$host" "$hub" "$user" "$user_pass"

        log "Дальше: забирай архив/папку с клиента:"
        log "  ls -la $CLIENTS_DIR"
        pause
        ;;
      2)
        local host admin_pass hub user user_pass
        host="$(prompt "IP или DNS сервера" "")"
        [[ -n "$host" ]] || die "Нужен host (IP/DNS)."

        admin_pass="$(prompt_secret "Пароль администратора SoftEther")"
        hub="$(prompt "Имя HUB" "$DEFAULT_HUB")"

        user="$(prompt "Логин пользователя" "vpn")"
        user_pass="$(prompt_secret "Пароль пользователя")"
        [[ -n "$user_pass" ]] || die "Пароль пользователя пустой."

        [[ -x "$VPNCMD" ]] || die "SoftEther не установлен. Сначала пункт 1."
        create_or_update_user "$admin_pass" "$hub" "$user" "$user_pass"
        generate_clients_bundle "$host" "$hub" "$user" "$user_pass"
        pause
        ;;
      3)
        local admin_pass hub user
        admin_pass="$(prompt_secret "Пароль администратора SoftEther")"
        hub="$(prompt "Имя HUB" "$DEFAULT_HUB")"
        user="$(prompt "Логин пользователя на удаление" "")"
        [[ -n "$user" ]] || die "Нужен логин."

        delete_user "$admin_pass" "$hub" "$user"
        rm -rf "$CLIENTS_DIR/$user" 2>/dev/null || true
        rm -f "$CLIENTS_DIR/"*"_${user}_clients.zip" 2>/dev/null || true
        log "Удалено."
        pause
        ;;
      4)
        local sure
        sure="$(prompt "Точно удалить ВСЁ? (yes/no)" "no")"
        [[ "$sure" == "yes" ]] || { log "Отменено."; pause; continue; }
        purge_all
        pause
        ;;
      0)
        exit 0
        ;;
      *)
        log "Неверный выбор."
        pause
        ;;
    esac
  done
}

# --------- CLI (non-interactive) ---------
MODE=""
HOST=""
ADMIN_PASS=""
HUB="$DEFAULT_HUB"
HUB_PASS=""
USER=""
USER_PASS=""

if [[ $# -gt 0 ]]; then
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install) MODE="install"; shift ;;
      --add-user) MODE="add"; shift ;;
      --del-user) MODE="del"; shift ;;
      --purge) MODE="purge"; shift ;;
      --host) HOST="${2:-}"; shift 2 ;;
      --admin-pass) ADMIN_PASS="${2:-}"; shift 2 ;;
      --hub) HUB="${2:-}"; shift 2 ;;
      --hub-pass) HUB_PASS="${2:-}"; shift 2 ;;
      --user) USER="${2:-}"; shift 2 ;;
      --user-pass) USER_PASS="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Неизвестный аргумент: $1" ;;
    esac
  done

  need_root
  ensure_dirs

  case "$MODE" in
    install)
      [[ -n "$HOST" && -n "$ADMIN_PASS" && -n "$USER" && -n "$USER_PASS" ]] || die "Для --install нужны: --host --admin-pass --user --user-pass (и опционально --hub --hub-pass)."
      [[ -n "$HUB_PASS" ]] || HUB_PASS="$ADMIN_PASS"
      install_deps
      install_softether
      install_systemd_unit
      configure_softether_minimal_sstp "$HOST" "$ADMIN_PASS" "$HUB" "$HUB_PASS"
      create_or_update_user "$ADMIN_PASS" "$HUB" "$USER" "$USER_PASS"
      generate_clients_bundle "$HOST" "$HUB" "$USER" "$USER_PASS"
      log "Готово. Клиенты в: $CLIENTS_DIR/$USER"
      ;;
    add)
      [[ -n "$HOST" && -n "$ADMIN_PASS" && -n "$USER" && -n "$USER_PASS" ]] || die "Для --add-user нужны: --host --admin-pass --user --user-pass (и опционально --hub)."
      [[ -x "$VPNCMD" ]] || die "SoftEther не установлен. Сначала --install."
      create_or_update_user "$ADMIN_PASS" "$HUB" "$USER" "$USER_PASS"
      generate_clients_bundle "$HOST" "$HUB" "$USER" "$USER_PASS"
      log "Готово. Клиенты в: $CLIENTS_DIR/$USER"
      ;;
    del)
      [[ -n "$ADMIN_PASS" && -n "$USER" ]] || die "Для --del-user нужны: --admin-pass --user (и опционально --hub)."
      [[ -x "$VPNCMD" ]] || die "SoftEther не установлен."
      delete_user "$ADMIN_PASS" "$HUB" "$USER"
      rm -rf "$CLIENTS_DIR/$USER" 2>/dev/null || true
      log "Пользователь удалён."
      ;;
    purge)
      purge_all
      ;;
    *)
      usage
      exit 1
      ;;
  esac

  exit 0
fi

# Interactive
need_root
ensure_dirs
if ! have_tty; then
  die "Запущено без TTY. Либо запускай интерактивно в терминале, либо передай параметры (см. --help)."
fi
main_menu
